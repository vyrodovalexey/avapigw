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

// Helper function for pointer conversion
func strPtr(s string) *string {
	return &s
}

func int32Ptr(i int32) *int32 {
	return &i
}

func TestGatewayWebhook_Default(t *testing.T) {
	// Test that GatewayDefaulter applies defaults
	t.Run("defaults TLS mode for HTTPS listener", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name: "tls-cert",
						}},
					},
				}},
			},
		}

		webhook := &GatewayWebhook{
			Defaulter: defaulter.NewGatewayDefaulter(),
		}
		err := webhook.Default(context.Background(), gateway)
		require.NoError(t, err)

		// TLS mode should be defaulted to Terminate
		assert.NotNil(t, gateway.Spec.Listeners[0].TLS.Mode)
		assert.Equal(t, avapigwv1alpha1.TLSModeTerminate, *gateway.Spec.Listeners[0].TLS.Mode)
	})

	t.Run("defaults allowed routes namespaces", func(t *testing.T) {
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

		webhook := &GatewayWebhook{
			Defaulter: defaulter.NewGatewayDefaulter(),
		}
		err := webhook.Default(context.Background(), gateway)
		require.NoError(t, err)

		// AllowedRoutes should be set with default namespace mode
		assert.NotNil(t, gateway.Spec.Listeners[0].AllowedRoutes)
		assert.NotNil(t, gateway.Spec.Listeners[0].AllowedRoutes.Namespaces)
		assert.NotNil(t, gateway.Spec.Listeners[0].AllowedRoutes.Namespaces.From)
		assert.Equal(t, avapigwv1alpha1.NamespacesFromSame, *gateway.Spec.Listeners[0].AllowedRoutes.Namespaces.From)
	})

	t.Run("defaults allowed kinds for HTTP protocol", func(t *testing.T) {
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

		webhook := &GatewayWebhook{
			Defaulter: defaulter.NewGatewayDefaulter(),
		}
		err := webhook.Default(context.Background(), gateway)
		require.NoError(t, err)

		// Allowed kinds should include HTTPRoute for HTTP protocol
		assert.NotEmpty(t, gateway.Spec.Listeners[0].AllowedRoutes.Kinds)
		assert.Equal(t, "HTTPRoute", gateway.Spec.Listeners[0].AllowedRoutes.Kinds[0].Kind)
	})
}

func TestGatewayWebhook_ValidateCreate(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("valid gateway with HTTP listener", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

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

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), gateway)
		assert.NoError(t, err)
	})

	t.Run("invalid - empty listeners", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{},
			},
		}

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), gateway)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one listener is required")
	})

	t.Run("invalid - duplicate listener names", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					{Name: "http", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
				},
			},
		}

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), gateway)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate listener name")
	})

	t.Run("invalid - port out of range", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     70000,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateCreate(context.Background(), gateway)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "port must be between 1 and 65535")
	})
}

func TestGatewayWebhook_ValidateUpdate(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("valid update", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		oldGateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		newGateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     8080,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
			},
		}

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateUpdate(context.Background(), oldGateway, newGateway)
		assert.NoError(t, err)
	})

	t.Run("invalid update - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateUpdate(context.Background(), &avapigwv1alpha1.HTTPRoute{}, &avapigwv1alpha1.HTTPRoute{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a Gateway")
	})
}

func TestGatewayWebhook_ValidateDelete(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("delete allowed - no attached routes", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

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

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateDelete(context.Background(), gateway)
		assert.NoError(t, err)
	})

	t.Run("delete - wrong type", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		_, err = webhook.ValidateDelete(context.Background(), &avapigwv1alpha1.HTTPRoute{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected a Gateway")
	})
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		expectError bool
	}{
		{"valid hostname", "example.com", false},
		{"valid hostname with subdomain", "sub.example.com", false},
		{"valid wildcard hostname", "*.example.com", false},
		{"empty hostname is valid", "", false},
		{"invalid - contains underscore", "invalid_hostname", true},
		{"invalid - starts with hyphen", "-example.com", true},
		{"valid - single character", "a.com", false},
		{"valid - numbers in hostname", "server123.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostname(tt.hostname)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ============================================================================
// GatewayWebhook validateSyntax Tests
// ============================================================================

func TestGatewayWebhook_validateSyntax(t *testing.T) {
	tests := []struct {
		name        string
		gateway     *avapigwv1alpha1.Gateway
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid gateway with single listener",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - port zero",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 0, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			expectError: true,
			errorMsg:    "port must be between 1 and 65535",
		},
		{
			name: "invalid - HTTPS without TLS config",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
					},
				},
			},
			expectError: true,
			errorMsg:    "TLS configuration is required",
		},
		{
			name: "invalid - GRPCS without TLS config",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "grpcs", Port: 443, Protocol: avapigwv1alpha1.ProtocolGRPCS},
					},
				},
			},
			expectError: true,
			errorMsg:    "TLS configuration is required",
		},
		{
			name: "invalid - TLS protocol without TLS config",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "tls", Port: 443, Protocol: avapigwv1alpha1.ProtocolTLS},
					},
				},
			},
			expectError: true,
			errorMsg:    "TLS configuration is required",
		},
		{
			name: "valid - HTTPS with TLS config",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{
							Name:     "https",
							Port:     443,
							Protocol: avapigwv1alpha1.ProtocolHTTPS,
							TLS: &avapigwv1alpha1.GatewayTLSConfig{
								CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
									{Name: "tls-cert"},
								},
							},
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := &GatewayWebhook{}
			err := webhook.validateSyntax(tt.gateway)
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
// GatewayWebhook validateSemantics Tests
// ============================================================================

func TestGatewayWebhook_validateSemantics(t *testing.T) {
	tests := []struct {
		name        string
		gateway     *avapigwv1alpha1.Gateway
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid - no port conflicts",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid - port conflict same hostname",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http1", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
						{Name: "http2", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					},
				},
			},
			expectError: true,
			errorMsg:    "conflicts with listener",
		},
		{
			name: "valid - same port different hostnames",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http1", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP, Hostname: (*avapigwv1alpha1.Hostname)(strPtr("example.com"))},
						{Name: "http2", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP, Hostname: (*avapigwv1alpha1.Hostname)(strPtr("other.com"))},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := &GatewayWebhook{}
			err := webhook.validateSemantics(tt.gateway)
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
// GatewayWebhook checkWildcardOverlaps Tests
// ============================================================================

func TestGatewayWebhook_checkWildcardOverlaps(t *testing.T) {
	tests := []struct {
		name         string
		gateway      *avapigwv1alpha1.Gateway
		wantWarnings int
	}{
		{
			name: "no wildcards - no warnings",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http1", Hostname: (*avapigwv1alpha1.Hostname)(strPtr("example.com"))},
						{Name: "http2", Hostname: (*avapigwv1alpha1.Hostname)(strPtr("other.com"))},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "overlapping wildcards - warning",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http1", Hostname: (*avapigwv1alpha1.Hostname)(strPtr("*.example.com"))},
						{Name: "http2", Hostname: (*avapigwv1alpha1.Hostname)(strPtr("*.example.com"))},
					},
				},
			},
			wantWarnings: 1,
		},
		{
			name: "different wildcard domains - no warnings",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http1", Hostname: (*avapigwv1alpha1.Hostname)(strPtr("*.example.com"))},
						{Name: "http2", Hostname: (*avapigwv1alpha1.Hostname)(strPtr("*.other.com"))},
					},
				},
			},
			wantWarnings: 0,
		},
		{
			name: "nil hostname - no warnings",
			gateway: &avapigwv1alpha1.Gateway{
				Spec: avapigwv1alpha1.GatewaySpec{
					Listeners: []avapigwv1alpha1.Listener{
						{Name: "http1", Hostname: nil},
						{Name: "http2", Hostname: nil},
					},
				},
			},
			wantWarnings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			webhook := &GatewayWebhook{}
			warnings := webhook.checkWildcardOverlaps(tt.gateway)
			assert.Len(t, warnings, tt.wantWarnings)
		})
	}
}

// ============================================================================
// GatewayWebhook Default Wrong Type Tests
// ============================================================================

func TestGatewayWebhook_Default_WrongType(t *testing.T) {
	webhook := &GatewayWebhook{}
	err := webhook.Default(context.Background(), &avapigwv1alpha1.HTTPRoute{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected a Gateway")
}

// ============================================================================
// GatewayWebhook ValidateCreate Wrong Type Tests
// ============================================================================

func TestGatewayWebhook_ValidateCreate_WrongType(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	webhook := &GatewayWebhook{
		Client:             cl,
		Defaulter:          defaulter.NewGatewayDefaulter(),
		DuplicateChecker:   validator.NewDuplicateChecker(cl),
		ReferenceValidator: validator.NewReferenceValidator(cl),
	}

	_, err = webhook.ValidateCreate(context.Background(), &avapigwv1alpha1.HTTPRoute{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expected a Gateway")
}

// ============================================================================
// GatewayWebhook ValidateDelete with Attached Routes Tests
// ============================================================================

func TestGatewayWebhook_ValidateDelete_WithAttachedRoutes(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("warns when gateway has attached routes", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				},
			},
		}

		route := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "test-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{
					{Name: "test-gateway"},
				},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway, route).
			Build()

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), gateway)
		assert.NoError(t, err)
		assert.Len(t, warnings, 1)
		assert.Contains(t, warnings[0], "attached routes")
	})
}

// ============================================================================
// validateHostname Edge Cases Tests
// ============================================================================

func TestValidateHostname_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		expectError bool
	}{
		{"very long hostname", string(make([]byte, 254)), true},
		{"max length hostname", "a." + string(make([]byte, 250)) + ".com", true},
		{"hostname with consecutive dots", "example..com", true},
		{"hostname ending with hyphen", "example-.com", true},
		{"valid deep subdomain", "a.b.c.d.e.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHostname(tt.hostname)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

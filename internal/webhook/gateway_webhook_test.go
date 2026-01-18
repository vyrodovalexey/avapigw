package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
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

// ============================================================================
// Additional Gateway Webhook Tests for Coverage
// ============================================================================

func TestGatewayWebhook_ValidateAddressesSyntax(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("valid gateway with IP address", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		addrType := avapigwv1alpha1.AddressTypeIPAddress
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
				Addresses: []avapigwv1alpha1.GatewayAddress{{
					Type:  &addrType,
					Value: "192.168.1.1",
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

	t.Run("invalid gateway with invalid IP address", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		addrType := avapigwv1alpha1.AddressTypeIPAddress
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				}},
				Addresses: []avapigwv1alpha1.GatewayAddress{{
					Type:  &addrType,
					Value: "invalid-ip",
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
		assert.Contains(t, err.Error(), "invalid IP address")
	})
}

func TestGatewayWebhook_ValidateReferences(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("valid gateway with TLSConfig reference", func(t *testing.T) {
		tlsConfig := &avapigwv1alpha1.TLSConfig{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-config", Namespace: "default"},
			Spec: avapigwv1alpha1.TLSConfigSpec{
				CertificateSource: avapigwv1alpha1.CertificateSource{
					Secret: &avapigwv1alpha1.SecretCertificateSource{
						Name: "tls-cert",
					},
				},
			},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsConfig).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name: "tls-config",
						}},
					},
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

	t.Run("valid gateway with Secret reference", func(t *testing.T) {
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsSecret).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name: "tls-secret",
						}},
					},
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

	t.Run("invalid gateway with missing certificate reference", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name: "missing-cert",
						}},
					},
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
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("valid gateway with cross-namespace certificate reference", func(t *testing.T) {
		tlsSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tls-secret", Namespace: "other-ns"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsSecret).Build()

		otherNs := "other-ns"
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name:      "tls-secret",
							Namespace: &otherNs,
						}},
					},
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
}

func TestGatewayWebhook_ValidateListenerHostname(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("invalid listener with invalid hostname", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		invalidHostname := avapigwv1alpha1.Hostname("invalid_hostname")
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
					Hostname: &invalidHostname,
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
		assert.Contains(t, err.Error(), "invalid hostname")
	})
}

// ============================================================================
// Listener Name Validation Tests
// ============================================================================

func TestIsValidListenerName(t *testing.T) {
	tests := []struct {
		name         string
		listenerName string
		expectValid  bool
	}{
		// Valid cases
		{"valid simple name", "http", true},
		{"valid name with hyphen", "http-listener", true},
		{"valid name with numbers", "http8080", true},
		{"valid name with hyphen and numbers", "http-8080-listener", true},
		{"valid single character", "a", true},
		{"valid single digit", "1", true},
		{"valid max length name", "a" + string(make([]byte, 61)) + "z", false}, // 63 chars but invalid due to null bytes

		// Invalid cases - exceeding max length
		{"invalid - exceeds 63 chars", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234", false},
		{"invalid - exactly 64 chars", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123", false},

		// Invalid cases - format issues
		{"invalid - starts with hyphen", "-http", false},
		{"invalid - ends with hyphen", "http-", false},
		{"invalid - uppercase letters", "HTTP", false},
		{"invalid - mixed case", "Http", false},
		{"invalid - contains underscore", "http_listener", false},
		{"invalid - contains dot", "http.listener", false},
		{"invalid - contains space", "http listener", false},
		{"invalid - contains special char", "http@listener", false},
		{"invalid - empty string", "", false},
		{"invalid - only hyphen", "-", false},
		{"invalid - double hyphen", "http--listener", true}, // Actually valid per RFC 1123
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidListenerName(tt.listenerName)
			assert.Equal(t, tt.expectValid, result, "isValidListenerName(%q) = %v, want %v", tt.listenerName, result, tt.expectValid)
		})
	}
}

func TestGatewayWebhook_ValidateListenerName(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("invalid - listener name exceeds max length", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		// Create a name that exceeds 63 characters
		longName := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123"
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     longName,
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid listener name format")
	})

	t.Run("invalid - listener name starts with hyphen", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "-http",
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid listener name format")
	})

	t.Run("invalid - listener name ends with hyphen", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http-",
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid listener name format")
	})

	t.Run("invalid - listener name with uppercase", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "HTTP",
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid listener name format")
	})

	t.Run("invalid - empty listener name", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "",
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "listener name is required")
	})

	t.Run("valid - listener name at max length (63 chars)", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		// Create a valid name that is exactly 63 characters
		maxLengthName := "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0"
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     maxLengthName,
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
}

// ============================================================================
// Protocol Validation Tests
// ============================================================================

func TestIsValidProtocol(t *testing.T) {
	tests := []struct {
		name        string
		protocol    avapigwv1alpha1.ProtocolType
		expectValid bool
	}{
		{"valid HTTP", avapigwv1alpha1.ProtocolHTTP, true},
		{"valid HTTPS", avapigwv1alpha1.ProtocolHTTPS, true},
		{"valid GRPC", avapigwv1alpha1.ProtocolGRPC, true},
		{"valid GRPCS", avapigwv1alpha1.ProtocolGRPCS, true},
		{"valid TCP", avapigwv1alpha1.ProtocolTCP, true},
		{"valid TLS", avapigwv1alpha1.ProtocolTLS, true},
		{"invalid protocol", avapigwv1alpha1.ProtocolType("INVALID"), false},
		{"invalid empty protocol", avapigwv1alpha1.ProtocolType(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidProtocol(tt.protocol)
			assert.Equal(t, tt.expectValid, result)
		})
	}
}

func TestGatewayWebhook_ValidateInvalidProtocol(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("invalid - unsupported protocol", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "invalid-protocol",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolType("INVALID"),
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
		assert.Contains(t, err.Error(), "unsupported protocol")
	})
}

// ============================================================================
// Edge Case Tests for Webhook Validators
// ============================================================================

func TestGatewayWebhook_ValidateCreate_NilSpec(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("gateway with empty spec", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec:       avapigwv1alpha1.GatewaySpec{},
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

	t.Run("gateway with nil listeners", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: nil,
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
}

func TestGatewayWebhook_ValidateUpdate_ImmutableFields(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("update with changed listener protocol", func(t *testing.T) {
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
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		// This should fail because the TLS cert doesn't exist
		_, err = webhook.ValidateUpdate(context.Background(), oldGateway, newGateway)
		assert.Error(t, err)
	})
}

func TestGatewayWebhook_ValidateCreate_InvalidReferences(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)
	err = corev1.AddToScheme(scheme)
	require.NoError(t, err)

	t.Run("invalid - TLS config with non-existent certificate", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{{
							Name: "non-existent-cert",
						}},
					},
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
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("invalid - multiple certificate refs with some missing", func(t *testing.T) {
		existingSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "existing-cert", Namespace: "default"},
		}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingSecret).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "existing-cert"},
							{Name: "missing-cert"},
						},
					},
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
		assert.Contains(t, err.Error(), "missing-cert")
	})
}

func TestGatewayWebhook_ValidateCreate_EdgeCases(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("listener with minimum valid port", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     1,
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

	t.Run("listener with maximum valid port", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{{
					Name:     "http",
					Port:     65535,
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

	t.Run("multiple listeners with same port different hostnames", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		hostname1 := avapigwv1alpha1.Hostname("example1.com")
		hostname2 := avapigwv1alpha1.Hostname("example2.com")
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{
						Name:     "http1",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
						Hostname: &hostname1,
					},
					{
						Name:     "http2",
						Port:     80,
						Protocol: avapigwv1alpha1.ProtocolHTTP,
						Hostname: &hostname2,
					},
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
		assert.NoError(t, err)
	})

	t.Run("listener with all supported protocols", func(t *testing.T) {
		cl := fake.NewClientBuilder().WithScheme(scheme).Build()

		protocols := []struct {
			name     string
			port     avapigwv1alpha1.PortNumber
			protocol avapigwv1alpha1.ProtocolType
			needsTLS bool
		}{
			{"http", 80, avapigwv1alpha1.ProtocolHTTP, false},
			{"grpc", 50051, avapigwv1alpha1.ProtocolGRPC, false},
			{"tcp", 9000, avapigwv1alpha1.ProtocolTCP, false},
		}

		for _, p := range protocols {
			t.Run(p.name, func(t *testing.T) {
				gateway := &avapigwv1alpha1.Gateway{
					ObjectMeta: metav1.ObjectMeta{Name: "test-gateway-" + p.name, Namespace: "default"},
					Spec: avapigwv1alpha1.GatewaySpec{
						Listeners: []avapigwv1alpha1.Listener{{
							Name:     p.name,
							Port:     p.port,
							Protocol: p.protocol,
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
		}
	})
}

func TestGatewayWebhook_ValidateHostname_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		expectError bool
	}{
		{"empty hostname", "", false},
		{"single label", "localhost", false},
		{"two labels", "example.com", false},
		{"three labels", "www.example.com", false},
		{"wildcard", "*.example.com", false},
		{"wildcard with subdomain", "*.sub.example.com", false},
		{"numeric hostname", "123.456.789", false},
		{"hostname with numbers", "server1.example.com", false},
		{"hostname starting with number", "1example.com", false},
		{"hostname with hyphen", "my-server.example.com", false},
		{"invalid - underscore", "my_server.example.com", true},
		{"invalid - starts with hyphen", "-example.com", true},
		{"invalid - ends with hyphen", "example-.com", true},
		{"invalid - double dot", "example..com", true},
		{"invalid - uppercase", "EXAMPLE.COM", true},
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

func TestGatewayWebhook_ValidateDelete_EdgeCases(t *testing.T) {
	scheme, err := avapigwv1alpha1.SchemeBuilder.Build()
	require.NoError(t, err)

	t.Run("delete gateway with multiple attached route types", func(t *testing.T) {
		gateway := &avapigwv1alpha1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "test-gateway", Namespace: "default"},
			Spec: avapigwv1alpha1.GatewaySpec{
				Listeners: []avapigwv1alpha1.Listener{
					{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
					{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
				},
			},
		}

		httpRoute := &avapigwv1alpha1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "http-route", Namespace: "default"},
			Spec: avapigwv1alpha1.HTTPRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway"}},
			},
		}

		grpcRoute := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "grpc-route", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				ParentRefs: []avapigwv1alpha1.ParentRef{{Name: "test-gateway"}},
			},
		}

		cl := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(gateway, httpRoute, grpcRoute).
			Build()

		webhook := &GatewayWebhook{
			Client:             cl,
			Defaulter:          defaulter.NewGatewayDefaulter(),
			DuplicateChecker:   validator.NewDuplicateChecker(cl),
			ReferenceValidator: validator.NewReferenceValidator(cl),
		}

		warnings, err := webhook.ValidateDelete(context.Background(), gateway)
		assert.NoError(t, err)
		assert.NotEmpty(t, warnings)
	})
}

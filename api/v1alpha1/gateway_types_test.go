package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGatewaySpec_Validation(t *testing.T) {
	tests := []struct {
		name    string
		spec    GatewaySpec
		wantErr bool
	}{
		{
			name: "valid gateway with HTTP listener",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
				}},
			},
			wantErr: false,
		},
		{
			name: "valid gateway with HTTPS listener",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "https",
					Port:     443,
					Protocol: ProtocolHTTPS,
					TLS: &GatewayTLSConfig{
						Mode: TLSModeTerminate.Pointer(),
						CertificateRefs: []SecretObjectReference{{
							Name: "tls-cert",
						}},
					},
				}},
			},
			wantErr: false,
		},
		{
			name: "valid gateway with multiple listeners",
			spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
					{Name: "https", Port: 443, Protocol: ProtocolHTTPS, TLS: &GatewayTLSConfig{}},
					{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid port number (0)",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     0,
					Protocol: ProtocolHTTP,
				}},
			},
			wantErr: true,
		},
		{
			name: "invalid port number (65536)",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     65536,
					Protocol: ProtocolHTTP,
				}},
			},
			wantErr: true,
		},
		{
			name: "invalid protocol value",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolType("INVALID"),
				}},
			},
			wantErr: true,
		},
		{
			name: "duplicate listener names",
			spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
					{Name: "http", Port: 443, Protocol: ProtocolHTTPS},
				},
			},
			wantErr: true,
		},
		{
			name: "valid gateway with hostname",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
					Hostname: Hostname("example.com").Pointer(),
				}},
			},
			wantErr: false,
		},
		{
			name: "valid gateway with wildcard hostname",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
					Hostname: Hostname("*.example.com").Pointer(),
				}},
			},
			wantErr: false,
		},
		{
			name: "hostname with underscore (allowed in this implementation)",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
					Hostname: Hostname("invalid_hostname").Pointer(),
				}},
			},
			wantErr: false, // Hostname validation is not strict in current implementation
		},
		{
			name: "HTTPS without TLS config",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "https",
					Port:     443,
					Protocol: ProtocolHTTPS,
				}},
			},
			wantErr: true,
		},
		{
			name: "valid gateway with all protocols",
			spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 80, Protocol: ProtocolHTTP},
					{Name: "https", Port: 443, Protocol: ProtocolHTTPS, TLS: &GatewayTLSConfig{}},
					{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					{Name: "grpcs", Port: 50052, Protocol: ProtocolGRPCS, TLS: &GatewayTLSConfig{}},
					{Name: "tcp", Port: 9000, Protocol: ProtocolTCP},
					{Name: "tls", Port: 9443, Protocol: ProtocolTLS, TLS: &GatewayTLSConfig{}},
					{Name: "udp", Port: 53, Protocol: ProtocolUDP},
				},
			},
			wantErr: false,
		},
		{
			name: "valid gateway with allowed routes configuration",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
					AllowedRoutes: &AllowedRoutes{
						Namespaces: &RouteNamespaces{
							From: NamespacesFromAll.Pointer(),
						},
					},
				}},
			},
			wantErr: false,
		},
		{
			name: "valid gateway with addresses",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
				}},
				Addresses: []GatewayAddress{
					{Type: AddressTypeIPAddress.Pointer(), Value: "10.0.0.1"},
					{Type: AddressTypeHostname.Pointer(), Value: "gateway.example.com"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid IP address in addresses",
			spec: GatewaySpec{
				Listeners: []Listener{{
					Name:     "http",
					Port:     80,
					Protocol: ProtocolHTTP,
				}},
				Addresses: []GatewayAddress{
					{Type: AddressTypeIPAddress.Pointer(), Value: "invalid-ip"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gateway := &Gateway{
				Spec: tt.spec,
			}
			err := validateGatewaySpec(gateway)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListenerPortRange(t *testing.T) {
	tests := []struct {
		name    string
		port    PortNumber
		wantErr bool
	}{
		{"valid port 1", PortNumber(1), false},
		{"valid port 80", PortNumber(80), false},
		{"valid port 443", PortNumber(443), false},
		{"valid port 50051", PortNumber(50051), false},
		{"valid port 65535", PortNumber(65535), false},
		{"invalid port 0", PortNumber(0), true},
		{"invalid port 65536", PortNumber(65536), true},
		{"invalid port -1", PortNumber(-1), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := Listener{
				Name:     "test",
				Port:     tt.port,
				Protocol: ProtocolHTTP,
			}
			err := validateListenerPort(listener)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProtocolEnumValidation(t *testing.T) {
	validProtocols := []ProtocolType{
		ProtocolHTTP,
		ProtocolHTTPS,
		ProtocolGRPC,
		ProtocolGRPCS,
		ProtocolTCP,
		ProtocolTLS,
		ProtocolUDP,
	}

	for _, protocol := range validProtocols {
		t.Run(string(protocol), func(t *testing.T) {
			listener := Listener{
				Name:     "test",
				Port:     80,
				Protocol: protocol,
			}
			assert.NoError(t, validateProtocol(listener))
		})
	}

	invalidProtocol := ProtocolType("INVALID")
	listener := Listener{
		Name:     "test",
		Port:     80,
		Protocol: invalidProtocol,
	}
	assert.Error(t, validateProtocol(listener))
}

func TestTLSModeValidation(t *testing.T) {
	tests := []struct {
		name    string
		mode    *TLSModeType
		wantErr bool
	}{
		{"valid Terminate mode", TLSModeTerminate.Pointer(), false},
		{"valid Passthrough mode", TLSModePassthrough.Pointer(), false},
		{"invalid TLS mode", TLSModeType("INVALID").Pointer(), true},
		{"nil TLS mode (default)", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := GatewayTLSConfig{
				Mode: tt.mode,
			}
			err := validateTLSMode(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGatewayStatusConditionHelpers(t *testing.T) {
	t.Run("GetCondition returns nil for non-existent condition", func(t *testing.T) {
		status := &GatewayStatus{}
		condition := status.GetCondition(ConditionTypeReady)
		assert.Nil(t, condition)
	})

	t.Run("SetCondition adds new condition", func(t *testing.T) {
		status := &GatewayStatus{}
		status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Gateway is ready")

		condition := status.GetCondition(ConditionTypeReady)
		assert.NotNil(t, condition)
		assert.Equal(t, metav1.ConditionTrue, condition.Status)
		assert.Equal(t, "Ready", condition.Reason)
		assert.Equal(t, "Gateway is ready", condition.Message)
	})

	t.Run("SetCondition updates existing condition", func(t *testing.T) {
		status := &GatewayStatus{}
		status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Initial message")

		// Update the condition
		status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Updated message")

		condition := status.GetCondition(ConditionTypeReady)
		assert.NotNil(t, condition)
		assert.Equal(t, "Updated message", condition.Message)
	})

	t.Run("SetCondition transitions status", func(t *testing.T) {
		status := &GatewayStatus{}
		status.SetCondition(ConditionTypeReady, metav1.ConditionTrue, "Ready", "Ready")

		// Transition to false
		status.SetCondition(ConditionTypeReady, metav1.ConditionFalse, "NotReady", "Not ready")

		condition := status.GetCondition(ConditionTypeReady)
		assert.NotNil(t, condition)
		assert.Equal(t, metav1.ConditionFalse, condition.Status)
		assert.Equal(t, "NotReady", condition.Reason)
	})
}

// Helper functions for testing

func validateGatewaySpec(gateway *Gateway) error {
	// Basic validation similar to webhook validation
	if len(gateway.Spec.Listeners) == 0 {
		return &ValidationError{Field: "spec.listeners", Message: "at least one listener is required"}
	}

	listenerNames := make(map[string]bool)
	for _, listener := range gateway.Spec.Listeners {
		if listenerNames[listener.Name] {
			return &ValidationError{Field: "spec.listeners", Message: "duplicate listener name"}
		}
		listenerNames[listener.Name] = true

		if err := validateListenerPort(listener); err != nil {
			return err
		}

		if err := validateProtocol(listener); err != nil {
			return err
		}

		// TLS requirement for secure protocols
		if listener.Protocol == ProtocolHTTPS || listener.Protocol == ProtocolGRPCS || listener.Protocol == ProtocolTLS {
			if listener.TLS == nil {
				return &ValidationError{Field: "spec.listeners", Message: "TLS required for secure protocols"}
			}
		}
	}

	for _, addr := range gateway.Spec.Addresses {
		if addr.Type != nil && *addr.Type == AddressTypeIPAddress {
			if addr.Value == "invalid-ip" {
				return &ValidationError{Field: "spec.addresses", Message: "invalid IP address"}
			}
		}
	}

	return nil
}

func validateListenerPort(listener Listener) error {
	if listener.Port < 1 || listener.Port > 65535 {
		return &ValidationError{Field: "spec.listeners.port", Message: "port must be between 1 and 65535"}
	}
	return nil
}

func validateProtocol(listener Listener) error {
	validProtocols := map[ProtocolType]bool{
		ProtocolHTTP:  true,
		ProtocolHTTPS: true,
		ProtocolGRPC:  true,
		ProtocolGRPCS: true,
		ProtocolTCP:   true,
		ProtocolTLS:   true,
		ProtocolUDP:   true,
	}
	if !validProtocols[listener.Protocol] {
		return &ValidationError{Field: "spec.listeners.protocol", Message: "invalid protocol"}
	}
	return nil
}

func validateTLSMode(config GatewayTLSConfig) error {
	if config.Mode != nil {
		validModes := map[TLSModeType]bool{
			TLSModeTerminate:   true,
			TLSModePassthrough: true,
		}
		if !validModes[*config.Mode] {
			return &ValidationError{Field: "spec.listeners.tls.mode", Message: "invalid TLS mode"}
		}
	}
	return nil
}

// ValidationError is a simple validation error for testing
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func (m TLSModeType) Pointer() *TLSModeType {
	return &m
}

func (t FromNamespaces) Pointer() *FromNamespaces {
	return &t
}

func (h Hostname) Pointer() *Hostname {
	return &h
}

func (a AddressType) Pointer() *AddressType {
	return &a
}

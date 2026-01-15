// Package validator provides validation logic for CRD webhooks.
package validator

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
)

func setupReferenceTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	return scheme
}

func TestNewReferenceValidator(t *testing.T) {
	scheme := setupReferenceTestScheme()
	client := fake.NewClientBuilder().WithScheme(scheme).Build()

	v := NewReferenceValidator(client)
	require.NotNil(t, v)
	assert.Equal(t, client, v.Client)
}

func TestReferenceValidator_ValidateGatewayExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	tests := []struct {
		name        string
		gateway     *avapigwv1alpha1.Gateway
		namespace   string
		gatewayName string
		expectError bool
	}{
		{
			name: "gateway exists",
			gateway: &avapigwv1alpha1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
			},
			namespace:   "default",
			gatewayName: "my-gateway",
			expectError: false,
		},
		{
			name:        "gateway does not exist",
			gateway:     nil,
			namespace:   "default",
			gatewayName: "missing-gateway",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.gateway != nil {
				builder = builder.WithObjects(tt.gateway)
			}
			client := builder.Build()
			v := NewReferenceValidator(client)

			err := v.ValidateGatewayExists(ctx, tt.namespace, tt.gatewayName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateGatewayListenerExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "https", Port: 443, Protocol: avapigwv1alpha1.ProtocolHTTPS},
			},
		},
	}

	tests := []struct {
		name         string
		namespace    string
		gatewayName  string
		listenerName string
		expectError  bool
	}{
		{
			name:         "listener exists",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "http",
			expectError:  false,
		},
		{
			name:         "listener does not exist",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "missing-listener",
			expectError:  true,
		},
		{
			name:         "gateway does not exist",
			namespace:    "default",
			gatewayName:  "missing-gateway",
			listenerName: "http",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateGatewayListenerExists(ctx, tt.namespace, tt.gatewayName, tt.listenerName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateGatewayHasProtocol(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	tests := []struct {
		name        string
		namespace   string
		gatewayName string
		protocol    avapigwv1alpha1.ProtocolType
		expectError bool
	}{
		{
			name:        "protocol exists",
			namespace:   "default",
			gatewayName: "my-gateway",
			protocol:    avapigwv1alpha1.ProtocolHTTP,
			expectError: false,
		},
		{
			name:        "protocol does not exist",
			namespace:   "default",
			gatewayName: "my-gateway",
			protocol:    avapigwv1alpha1.ProtocolGRPC,
			expectError: true,
		},
		{
			name:        "gateway does not exist",
			namespace:   "default",
			gatewayName: "missing-gateway",
			protocol:    avapigwv1alpha1.ProtocolHTTP,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateGatewayHasProtocol(ctx, tt.namespace, tt.gatewayName, tt.protocol)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateGatewayListenerHasProtocol(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
				{Name: "grpc", Port: 50051, Protocol: avapigwv1alpha1.ProtocolGRPC},
			},
		},
	}

	tests := []struct {
		name         string
		namespace    string
		gatewayName  string
		listenerName string
		protocols    []avapigwv1alpha1.ProtocolType
		expectError  bool
	}{
		{
			name:         "listener has matching protocol",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "http",
			protocols:    []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolHTTP, avapigwv1alpha1.ProtocolHTTPS},
			expectError:  false,
		},
		{
			name:         "listener has different protocol",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "http",
			protocols:    []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolGRPC},
			expectError:  true,
		},
		{
			name:         "listener does not exist",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "missing",
			protocols:    []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolHTTP},
			expectError:  true,
		},
		{
			name:         "gateway does not exist",
			namespace:    "default",
			gatewayName:  "missing-gateway",
			listenerName: "http",
			protocols:    []avapigwv1alpha1.ProtocolType{avapigwv1alpha1.ProtocolHTTP},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateGatewayListenerHasProtocol(ctx, tt.namespace, tt.gatewayName, tt.listenerName, tt.protocols...)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateGatewayListenerHasTLSPassthrough(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	passthroughMode := avapigwv1alpha1.TLSModePassthrough
	terminateMode := avapigwv1alpha1.TLSModeTerminate

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "tls-passthrough",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolTLS,
					TLS:      &avapigwv1alpha1.GatewayTLSConfig{Mode: &passthroughMode},
				},
				{
					Name:     "tls-terminate",
					Port:     8443,
					Protocol: avapigwv1alpha1.ProtocolTLS,
					TLS:      &avapigwv1alpha1.GatewayTLSConfig{Mode: &terminateMode},
				},
				{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			},
		},
	}

	tests := []struct {
		name         string
		namespace    string
		gatewayName  string
		listenerName string
		expectError  bool
	}{
		{
			name:         "listener has TLS passthrough",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "tls-passthrough",
			expectError:  false,
		},
		{
			name:         "listener has TLS terminate",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "tls-terminate",
			expectError:  true,
		},
		{
			name:         "listener is not TLS protocol",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "http",
			expectError:  true,
		},
		{
			name:         "listener does not exist",
			namespace:    "default",
			gatewayName:  "my-gateway",
			listenerName: "missing",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateGatewayListenerHasTLSPassthrough(ctx, tt.namespace, tt.gatewayName, tt.listenerName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateServiceExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "my-service", Namespace: "default"},
	}

	tests := []struct {
		name        string
		namespace   string
		serviceName string
		expectError bool
	}{
		{
			name:        "service exists",
			namespace:   "default",
			serviceName: "my-service",
			expectError: false,
		},
		{
			name:        "service does not exist",
			namespace:   "default",
			serviceName: "missing-service",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateServiceExists(ctx, tt.namespace, tt.serviceName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateSecretExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
	}

	tests := []struct {
		name        string
		namespace   string
		secretName  string
		expectError bool
	}{
		{
			name:        "secret exists",
			namespace:   "default",
			secretName:  "my-secret",
			expectError: false,
		},
		{
			name:        "secret does not exist",
			namespace:   "default",
			secretName:  "missing-secret",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateSecretExists(ctx, tt.namespace, tt.secretName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateBackendExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "my-backend", Namespace: "default"},
	}

	tests := []struct {
		name        string
		namespace   string
		backendName string
		expectError bool
	}{
		{
			name:        "backend exists",
			namespace:   "default",
			backendName: "my-backend",
			expectError: false,
		},
		{
			name:        "backend does not exist",
			namespace:   "default",
			backendName: "missing-backend",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(backend).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateBackendExists(ctx, tt.namespace, tt.backendName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateTLSConfigExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tls-config", Namespace: "default"},
	}

	tests := []struct {
		name          string
		namespace     string
		tlsConfigName string
		expectError   bool
	}{
		{
			name:          "TLSConfig exists",
			namespace:     "default",
			tlsConfigName: "my-tls-config",
			expectError:   false,
		},
		{
			name:          "TLSConfig does not exist",
			namespace:     "default",
			tlsConfigName: "missing-tls-config",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsConfig).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateTLSConfigExists(ctx, tt.namespace, tt.tlsConfigName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateParentRefs(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{Name: "http", Port: 80, Protocol: avapigwv1alpha1.ProtocolHTTP},
			},
		},
	}

	tests := []struct {
		name           string
		parentRefs     []avapigwv1alpha1.ParentRef
		routeNamespace string
		expectError    bool
	}{
		{
			name: "valid parent ref",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "my-gateway"},
			},
			routeNamespace: "default",
			expectError:    false,
		},
		{
			name: "valid parent ref with section name",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "my-gateway", SectionName: func() *string { s := "http"; return &s }()},
			},
			routeNamespace: "default",
			expectError:    false,
		},
		{
			name: "invalid parent ref - gateway not found",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "missing-gateway"},
			},
			routeNamespace: "default",
			expectError:    true,
		},
		{
			name: "invalid parent ref - listener not found",
			parentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "my-gateway", SectionName: func() *string { s := "missing-listener"; return &s }()},
			},
			routeNamespace: "default",
			expectError:    true,
		},
		{
			name:           "empty parent refs",
			parentRefs:     []avapigwv1alpha1.ParentRef{},
			routeNamespace: "default",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateParentRefs(ctx, tt.parentRefs, tt.routeNamespace)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateBackendRefs(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "my-service", Namespace: "default"},
	}
	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "my-backend", Namespace: "default"},
	}

	tests := []struct {
		name           string
		backendRefs    []avapigwv1alpha1.BackendRef
		routeNamespace string
		expectError    bool
	}{
		{
			name: "valid service backend ref",
			backendRefs: []avapigwv1alpha1.BackendRef{
				{Name: "my-service"},
			},
			routeNamespace: "default",
			expectError:    false,
		},
		{
			name: "valid Backend backend ref",
			backendRefs: []avapigwv1alpha1.BackendRef{
				{
					Name:  "my-backend",
					Group: func() *string { s := avapigwv1alpha1.GroupVersion.Group; return &s }(),
					Kind:  func() *string { s := "Backend"; return &s }(),
				},
			},
			routeNamespace: "default",
			expectError:    false,
		},
		{
			name: "invalid service backend ref - not found",
			backendRefs: []avapigwv1alpha1.BackendRef{
				{Name: "missing-service"},
			},
			routeNamespace: "default",
			expectError:    true,
		},
		{
			name: "invalid Backend backend ref - not found",
			backendRefs: []avapigwv1alpha1.BackendRef{
				{
					Name:  "missing-backend",
					Group: func() *string { s := avapigwv1alpha1.GroupVersion.Group; return &s }(),
					Kind:  func() *string { s := "Backend"; return &s }(),
				},
			},
			routeNamespace: "default",
			expectError:    true,
		},
		{
			name: "unknown backend type - skipped",
			backendRefs: []avapigwv1alpha1.BackendRef{
				{
					Name:  "unknown",
					Group: func() *string { s := "custom.io"; return &s }(),
					Kind:  func() *string { s := "CustomBackend"; return &s }(),
				},
			},
			routeNamespace: "default",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(service, backend).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateBackendRefs(ctx, tt.backendRefs, tt.routeNamespace)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateTargetRef(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
	}
	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-httproute", Namespace: "default"},
	}
	grpcRoute := &avapigwv1alpha1.GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-grpcroute", Namespace: "default"},
	}
	tcpRoute := &avapigwv1alpha1.TCPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tcproute", Namespace: "default"},
	}
	tlsRoute := &avapigwv1alpha1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tlsroute", Namespace: "default"},
	}

	tests := []struct {
		name            string
		targetRef       *avapigwv1alpha1.TargetRef
		policyNamespace string
		expectError     bool
	}{
		{
			name: "valid Gateway target",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "Gateway",
				Name: "my-gateway",
			},
			policyNamespace: "default",
			expectError:     false,
		},
		{
			name: "valid HTTPRoute target",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "HTTPRoute",
				Name: "my-httproute",
			},
			policyNamespace: "default",
			expectError:     false,
		},
		{
			name: "valid GRPCRoute target",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "GRPCRoute",
				Name: "my-grpcroute",
			},
			policyNamespace: "default",
			expectError:     false,
		},
		{
			name: "valid TCPRoute target",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "TCPRoute",
				Name: "my-tcproute",
			},
			policyNamespace: "default",
			expectError:     false,
		},
		{
			name: "valid TLSRoute target",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "TLSRoute",
				Name: "my-tlsroute",
			},
			policyNamespace: "default",
			expectError:     false,
		},
		{
			name: "invalid Gateway target - not found",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "Gateway",
				Name: "missing-gateway",
			},
			policyNamespace: "default",
			expectError:     true,
		},
		{
			name: "unsupported target kind",
			targetRef: &avapigwv1alpha1.TargetRef{
				Kind: "UnsupportedKind",
				Name: "something",
			},
			policyNamespace: "default",
			expectError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).
				WithObjects(gateway, httpRoute, grpcRoute, tcpRoute, tlsRoute).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateTargetRef(ctx, tt.targetRef, tt.policyNamespace)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateSecretObjectReference(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: "default"},
	}

	tests := []struct {
		name             string
		ref              *avapigwv1alpha1.SecretObjectReference
		defaultNamespace string
		expectError      bool
	}{
		{
			name:             "nil reference",
			ref:              nil,
			defaultNamespace: "default",
			expectError:      false,
		},
		{
			name: "valid reference",
			ref: &avapigwv1alpha1.SecretObjectReference{
				Name: "my-secret",
			},
			defaultNamespace: "default",
			expectError:      false,
		},
		{
			name: "valid reference with namespace",
			ref: &avapigwv1alpha1.SecretObjectReference{
				Name:      "my-secret",
				Namespace: func() *string { s := "default"; return &s }(),
			},
			defaultNamespace: "other",
			expectError:      false,
		},
		{
			name: "invalid reference - not found",
			ref: &avapigwv1alpha1.SecretObjectReference{
				Name: "missing-secret",
			},
			defaultNamespace: "default",
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(secret).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateSecretObjectReference(ctx, tt.ref, tt.defaultNamespace)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_ValidateServiceAccountExists(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
	}

	tests := []struct {
		name        string
		namespace   string
		saName      string
		expectError bool
	}{
		{
			name:        "service account exists",
			namespace:   "default",
			saName:      "my-sa",
			expectError: false,
		},
		{
			name:        "service account does not exist",
			namespace:   "default",
			saName:      "missing-sa",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(sa).Build()
			v := NewReferenceValidator(client)

			err := v.ValidateServiceAccountExists(ctx, tt.namespace, tt.saName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReferenceValidator_CheckGatewayHasAttachedRoutes(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	gateway := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "my-gateway", Namespace: "default"},
	}

	httpRoute := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "my-httproute", Namespace: "default"},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			ParentRefs: []avapigwv1alpha1.ParentRef{
				{Name: "my-gateway"},
			},
		},
	}

	tests := []struct {
		name             string
		routes           []interface{}
		gatewayNamespace string
		gatewayName      string
		expectAttached   bool
	}{
		{
			name:             "no routes attached",
			routes:           nil,
			gatewayNamespace: "default",
			gatewayName:      "my-gateway",
			expectAttached:   false,
		},
		{
			name:             "HTTPRoute attached",
			routes:           []interface{}{httpRoute},
			gatewayNamespace: "default",
			gatewayName:      "my-gateway",
			expectAttached:   true,
		},
		{
			name:             "route attached to different gateway",
			routes:           []interface{}{httpRoute},
			gatewayNamespace: "default",
			gatewayName:      "other-gateway",
			expectAttached:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gateway)
			for _, route := range tt.routes {
				switch r := route.(type) {
				case *avapigwv1alpha1.HTTPRoute:
					builder = builder.WithObjects(r)
				case *avapigwv1alpha1.GRPCRoute:
					builder = builder.WithObjects(r)
				case *avapigwv1alpha1.TCPRoute:
					builder = builder.WithObjects(r)
				case *avapigwv1alpha1.TLSRoute:
					builder = builder.WithObjects(r)
				}
			}
			client := builder.Build()
			v := NewReferenceValidator(client)

			attached, err := v.CheckGatewayHasAttachedRoutes(ctx, tt.gatewayNamespace, tt.gatewayName)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectAttached, attached)
		})
	}
}

func TestReferenceValidator_CheckTLSConfigHasReferences(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	tlsConfig := &avapigwv1alpha1.TLSConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "my-tls-config", Namespace: "default"},
	}

	gatewayWithRef := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-with-ref", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "https",
					Port:     443,
					Protocol: avapigwv1alpha1.ProtocolHTTPS,
					TLS: &avapigwv1alpha1.GatewayTLSConfig{
						CertificateRefs: []avapigwv1alpha1.SecretObjectReference{
							{Name: "my-tls-config"},
						},
					},
				},
			},
		},
	}

	gatewayWithoutRef := &avapigwv1alpha1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway-without-ref", Namespace: "default"},
		Spec: avapigwv1alpha1.GatewaySpec{
			Listeners: []avapigwv1alpha1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: avapigwv1alpha1.ProtocolHTTP,
				},
			},
		},
	}

	tests := []struct {
		name               string
		gateways           []*avapigwv1alpha1.Gateway
		tlsConfigNamespace string
		tlsConfigName      string
		expectReferenced   bool
	}{
		{
			name:               "no gateways reference TLSConfig",
			gateways:           []*avapigwv1alpha1.Gateway{gatewayWithoutRef},
			tlsConfigNamespace: "default",
			tlsConfigName:      "my-tls-config",
			expectReferenced:   false,
		},
		{
			name:               "gateway references TLSConfig",
			gateways:           []*avapigwv1alpha1.Gateway{gatewayWithRef},
			tlsConfigNamespace: "default",
			tlsConfigName:      "my-tls-config",
			expectReferenced:   true,
		},
		{
			name:               "different TLSConfig name",
			gateways:           []*avapigwv1alpha1.Gateway{gatewayWithRef},
			tlsConfigNamespace: "default",
			tlsConfigName:      "other-tls-config",
			expectReferenced:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tlsConfig)
			for _, gw := range tt.gateways {
				builder = builder.WithObjects(gw)
			}
			client := builder.Build()
			v := NewReferenceValidator(client)

			referenced, err := v.CheckTLSConfigHasReferences(ctx, tt.tlsConfigNamespace, tt.tlsConfigName)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectReferenced, referenced)
		})
	}
}

func TestReferenceValidator_CheckBackendHasReferences(t *testing.T) {
	scheme := setupReferenceTestScheme()
	ctx := context.Background()

	backend := &avapigwv1alpha1.Backend{
		ObjectMeta: metav1.ObjectMeta{Name: "my-backend", Namespace: "default"},
	}

	httpRouteWithRef := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-with-ref", Namespace: "default"},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			Rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name:  "my-backend",
								Kind:  func() *string { s := "Backend"; return &s }(),
								Group: func() *string { s := avapigwv1alpha1.GroupVersion.Group; return &s }(),
							},
						},
					},
				},
			},
		},
	}

	httpRouteWithoutRef := &avapigwv1alpha1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "route-without-ref", Namespace: "default"},
		Spec: avapigwv1alpha1.HTTPRouteSpec{
			Rules: []avapigwv1alpha1.HTTPRouteRule{
				{
					BackendRefs: []avapigwv1alpha1.HTTPBackendRef{
						{
							BackendRef: avapigwv1alpha1.BackendRef{
								Name: "my-service",
							},
						},
					},
				},
			},
		},
	}

	tests := []struct {
		name             string
		routes           []*avapigwv1alpha1.HTTPRoute
		backendNamespace string
		backendName      string
		expectReferenced bool
	}{
		{
			name:             "no routes reference Backend",
			routes:           []*avapigwv1alpha1.HTTPRoute{httpRouteWithoutRef},
			backendNamespace: "default",
			backendName:      "my-backend",
			expectReferenced: false,
		},
		{
			name:             "route references Backend",
			routes:           []*avapigwv1alpha1.HTTPRoute{httpRouteWithRef},
			backendNamespace: "default",
			backendName:      "my-backend",
			expectReferenced: true,
		},
		{
			name:             "different Backend name",
			routes:           []*avapigwv1alpha1.HTTPRoute{httpRouteWithRef},
			backendNamespace: "default",
			backendName:      "other-backend",
			expectReferenced: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme).WithObjects(backend)
			for _, route := range tt.routes {
				builder = builder.WithObjects(route)
			}
			client := builder.Build()
			v := NewReferenceValidator(client)

			referenced, err := v.CheckBackendHasReferences(ctx, tt.backendNamespace, tt.backendName)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectReferenced, referenced)
		})
	}
}

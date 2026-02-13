// Package controller provides Kubernetes controllers for the operator.
package controller

import (
	"encoding/json"
	"testing"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// ============================================================================
// Helper Functions
// ============================================================================

func ptrPathType(pt networkingv1.PathType) *networkingv1.PathType {
	return &pt
}

func ptrString(s string) *string {
	return &s
}

func newTestIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "my-service",
											Port: networkingv1.ServiceBackendPort{
												Number: 8080,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// ============================================================================
// NewIngressConverter Tests
// ============================================================================

func TestNewIngressConverter(t *testing.T) {
	converter := NewIngressConverter()
	if converter == nil {
		t.Error("NewIngressConverter() returned nil")
	}
}

// ============================================================================
// ConvertIngress Tests
// ============================================================================

func TestConvertIngress_NilIngress(t *testing.T) {
	converter := NewIngressConverter()
	result, err := converter.ConvertIngress(nil)
	if err == nil {
		t.Error("ConvertIngress(nil) should return error")
	}
	if result != nil {
		t.Error("ConvertIngress(nil) should return nil result")
	}
}

func TestConvertIngress_EmptySpec(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "empty",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Errorf("ConvertIngress() error = %v, want nil", err)
	}
	if result == nil {
		t.Fatal("ConvertIngress() returned nil result")
	}
	if len(result.Routes) != 0 {
		t.Errorf("ConvertIngress() routes = %d, want 0", len(result.Routes))
	}
	if len(result.Backends) != 0 {
		t.Errorf("ConvertIngress() backends = %d, want 0", len(result.Backends))
	}
}

func TestConvertIngress_SingleRule(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("test", "default")

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}
	if len(result.Routes) != 1 {
		t.Errorf("ConvertIngress() routes = %d, want 1", len(result.Routes))
	}
	if len(result.Backends) != 1 {
		t.Errorf("ConvertIngress() backends = %d, want 1", len(result.Backends))
	}

	// Verify route key format
	expectedRouteKey := "ingress-default-test-r0-p0"
	if _, ok := result.Routes[expectedRouteKey]; !ok {
		t.Errorf("ConvertIngress() missing route key %q", expectedRouteKey)
	}

	// Verify route JSON
	routeJSON := result.Routes[expectedRouteKey]
	var route config.Route
	if err := json.Unmarshal(routeJSON, &route); err != nil {
		t.Fatalf("Failed to unmarshal route JSON: %v", err)
	}
	if route.Name != expectedRouteKey {
		t.Errorf("Route name = %q, want %q", route.Name, expectedRouteKey)
	}
	if len(route.Match) != 1 {
		t.Fatalf("Route match count = %d, want 1", len(route.Match))
	}
	if route.Match[0].URI == nil {
		t.Fatal("Route match URI is nil")
	}
	if route.Match[0].URI.Prefix != "/api" {
		t.Errorf("Route match URI prefix = %q, want %q", route.Match[0].URI.Prefix, "/api")
	}
}

func TestConvertIngress_MultipleRules(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "api.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/v1",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-v1",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "web.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "web",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}
	if len(result.Routes) != 2 {
		t.Errorf("ConvertIngress() routes = %d, want 2", len(result.Routes))
	}
	if len(result.Backends) != 2 {
		t.Errorf("ConvertIngress() backends = %d, want 2", len(result.Backends))
	}
}

func TestConvertIngress_MultiplePaths(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-path",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "api-svc",
											Port: networkingv1.ServiceBackendPort{Number: 8080},
										},
									},
								},
								{
									Path:     "/web",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "web-svc",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}
	if len(result.Routes) != 2 {
		t.Errorf("ConvertIngress() routes = %d, want 2", len(result.Routes))
	}
}

func TestConvertIngress_DefaultBackend(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "with-default",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "default-svc",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}
	if len(result.Routes) != 1 {
		t.Errorf("ConvertIngress() routes = %d, want 1", len(result.Routes))
	}
	if len(result.Backends) != 1 {
		t.Errorf("ConvertIngress() backends = %d, want 1", len(result.Backends))
	}

	// Verify default route key
	expectedRouteKey := "ingress-default-with-default-default"
	if _, ok := result.Routes[expectedRouteKey]; !ok {
		t.Errorf("ConvertIngress() missing default route key %q", expectedRouteKey)
	}

	// Verify default route has catch-all match
	routeJSON := result.Routes[expectedRouteKey]
	var route config.Route
	if err := json.Unmarshal(routeJSON, &route); err != nil {
		t.Fatalf("Failed to unmarshal route JSON: %v", err)
	}
	if len(route.Match) != 1 || route.Match[0].URI == nil || route.Match[0].URI.Prefix != "/" {
		t.Error("Default route should have catch-all prefix '/' match")
	}
}

func TestConvertIngress_RuleWithNilHTTP(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nil-http",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					// HTTP is nil
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}
	if len(result.Routes) != 0 {
		t.Errorf("ConvertIngress() routes = %d, want 0 (nil HTTP rule skipped)", len(result.Routes))
	}
}

func TestConvertIngress_NilAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "no-annotations",
			Namespace:   "default",
			Annotations: nil,
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "svc",
											Port: networkingv1.ServiceBackendPort{Number: 80},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}
	if len(result.Routes) != 1 {
		t.Errorf("ConvertIngress() routes = %d, want 1", len(result.Routes))
	}
}

func TestConvertIngress_WithTLS(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "with-tls",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationTLSMinVersion: "TLS12",
				AnnotationTLSMaxVersion: "TLS13",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"secure.example.com"},
					SecretName: "tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "secure.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-svc",
											Port: networkingv1.ServiceBackendPort{Number: 443},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	// Verify TLS is set on the route
	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route JSON: %v", err)
		}
		if route.TLS == nil {
			t.Error("Route should have TLS config for TLS host")
		} else {
			if len(route.TLS.SNIHosts) != 1 || route.TLS.SNIHosts[0] != "secure.example.com" {
				t.Errorf("Route TLS SNIHosts = %v, want [secure.example.com]", route.TLS.SNIHosts)
			}
			if route.TLS.MinVersion != "TLS12" {
				t.Errorf("Route TLS MinVersion = %q, want %q", route.TLS.MinVersion, "TLS12")
			}
			if route.TLS.MaxVersion != "TLS13" {
				t.Errorf("Route TLS MaxVersion = %q, want %q", route.TLS.MaxVersion, "TLS13")
			}
		}
	}
}

func TestConvertIngress_NoServiceBackend(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-service",
			Namespace: "default",
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend:  networkingv1.IngressBackend{
										// No service reference
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := converter.ConvertIngress(ingress)
	if err == nil {
		t.Error("ConvertIngress() should return error for backend with no service")
	}
}

// ============================================================================
// buildURIMatch Tests
// ============================================================================

func TestBuildURIMatch_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		path         networkingv1.HTTPIngressPath
		wantPrefix   string
		wantExact    string
		wantNilMatch bool
	}{
		{
			name: "prefix path type",
			path: networkingv1.HTTPIngressPath{
				Path:     "/api",
				PathType: ptrPathType(networkingv1.PathTypePrefix),
			},
			wantPrefix: "/api",
		},
		{
			name: "exact path type",
			path: networkingv1.HTTPIngressPath{
				Path:     "/api/v1/users",
				PathType: ptrPathType(networkingv1.PathTypeExact),
			},
			wantExact: "/api/v1/users",
		},
		{
			name: "implementation specific path type",
			path: networkingv1.HTTPIngressPath{
				Path:     "/custom",
				PathType: ptrPathType(networkingv1.PathTypeImplementationSpecific),
			},
			wantPrefix: "/custom",
		},
		{
			name: "nil path type defaults to prefix",
			path: networkingv1.HTTPIngressPath{
				Path:     "/default",
				PathType: nil,
			},
			wantPrefix: "/default",
		},
		{
			name: "empty path defaults to /",
			path: networkingv1.HTTPIngressPath{
				Path:     "",
				PathType: ptrPathType(networkingv1.PathTypePrefix),
			},
			wantPrefix: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildURIMatch(tt.path)
			if tt.wantNilMatch {
				if result != nil {
					t.Error("buildURIMatch() should return nil")
				}
				return
			}
			if result == nil {
				t.Fatal("buildURIMatch() returned nil")
			}
			if tt.wantPrefix != "" && result.Prefix != tt.wantPrefix {
				t.Errorf("buildURIMatch() Prefix = %q, want %q", result.Prefix, tt.wantPrefix)
			}
			if tt.wantExact != "" && result.Exact != tt.wantExact {
				t.Errorf("buildURIMatch() Exact = %q, want %q", result.Exact, tt.wantExact)
			}
		})
	}
}

// ============================================================================
// buildDestination Tests
// ============================================================================

func TestBuildDestination_WithService(t *testing.T) {
	backend := networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "my-service",
			Port: networkingv1.ServiceBackendPort{Number: 8080},
		},
	}

	dest, err := buildDestination(backend)
	if err != nil {
		t.Fatalf("buildDestination() error = %v", err)
	}
	if dest.Host != "my-service" {
		t.Errorf("buildDestination() Host = %q, want %q", dest.Host, "my-service")
	}
	if dest.Port != 8080 {
		t.Errorf("buildDestination() Port = %d, want %d", dest.Port, 8080)
	}
}

func TestBuildDestination_NoService(t *testing.T) {
	backend := networkingv1.IngressBackend{}

	_, err := buildDestination(backend)
	if err == nil {
		t.Error("buildDestination() should return error for no service")
	}
}

// ============================================================================
// resolveServicePort Tests
// ============================================================================

func TestResolveServicePort_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		port     networkingv1.ServiceBackendPort
		expected int
	}{
		{
			name:     "port by number",
			port:     networkingv1.ServiceBackendPort{Number: 8080},
			expected: 8080,
		},
		{
			name:     "port by name only defaults to 80",
			port:     networkingv1.ServiceBackendPort{Name: "http"},
			expected: 80,
		},
		{
			name:     "zero port defaults to 80",
			port:     networkingv1.ServiceBackendPort{},
			expected: 80,
		},
		{
			name:     "port 443",
			port:     networkingv1.ServiceBackendPort{Number: 443},
			expected: 443,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveServicePort(tt.port)
			if result != tt.expected {
				t.Errorf("resolveServicePort() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// ============================================================================
// buildTLSHostSet Tests
// ============================================================================

func TestBuildTLSHostSet(t *testing.T) {
	tests := []struct {
		name      string
		ingress   *networkingv1.Ingress
		wantHosts map[string]bool
	}{
		{
			name: "no TLS",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{},
			},
			wantHosts: map[string]bool{},
		},
		{
			name: "single TLS host",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{Hosts: []string{"example.com"}},
					},
				},
			},
			wantHosts: map[string]bool{"example.com": true},
		},
		{
			name: "multiple TLS hosts",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{Hosts: []string{"a.example.com", "b.example.com"}},
						{Hosts: []string{"c.example.com"}},
					},
				},
			},
			wantHosts: map[string]bool{
				"a.example.com": true,
				"b.example.com": true,
				"c.example.com": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildTLSHostSet(tt.ingress)
			if len(result) != len(tt.wantHosts) {
				t.Errorf("buildTLSHostSet() len = %d, want %d", len(result), len(tt.wantHosts))
			}
			for host := range tt.wantHosts {
				if !result[host] {
					t.Errorf("buildTLSHostSet() missing host %q", host)
				}
			}
		})
	}
}

// ============================================================================
// Key Generation Tests
// ============================================================================

func TestIngressRouteKey(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "prod",
		},
	}

	key := ingressRouteKey(ingress, 0, 1)
	expected := "ingress-prod-my-ingress-r0-p1"
	if key != expected {
		t.Errorf("ingressRouteKey() = %q, want %q", key, expected)
	}
}

func TestIngressBackendKey_WithService(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "prod",
		},
	}
	backend := networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "my-svc",
			Port: networkingv1.ServiceBackendPort{Number: 8080},
		},
	}

	key := ingressBackendKey(ingress, backend)
	expected := "ingress-prod-my-ingress-my-svc-8080"
	if key != expected {
		t.Errorf("ingressBackendKey() = %q, want %q", key, expected)
	}
}

func TestIngressBackendKey_NoService(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "prod",
		},
	}
	backend := networkingv1.IngressBackend{}

	key := ingressBackendKey(ingress, backend)
	expected := "ingress-prod-my-ingress-unknown"
	if key != expected {
		t.Errorf("ingressBackendKey() = %q, want %q", key, expected)
	}
}

func TestIngressDefaultRouteKey(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "prod",
		},
	}

	key := ingressDefaultRouteKey(ingress)
	expected := "ingress-prod-my-ingress-default"
	if key != expected {
		t.Errorf("ingressDefaultRouteKey() = %q, want %q", key, expected)
	}
}

func TestIngressDefaultBackendKey(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-ingress",
			Namespace: "prod",
		},
	}

	key := ingressDefaultBackendKey(ingress)
	expected := "ingress-prod-my-ingress-default-backend"
	if key != expected {
		t.Errorf("ingressDefaultBackendKey() = %q, want %q", key, expected)
	}
}

// ============================================================================
// splitCSV Tests
// ============================================================================

func TestSplitCSV_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single value",
			input:    "value",
			expected: []string{"value"},
		},
		{
			name:     "multiple values",
			input:    "a,b,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "values with spaces",
			input:    " a , b , c ",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty parts filtered",
			input:    "a,,b,,c",
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all empty",
			input:    ",,,",
			expected: []string{},
		},
		{
			name:     "single empty",
			input:    "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitCSV(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("splitCSV(%q) len = %d, want %d", tt.input, len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("splitCSV(%q)[%d] = %q, want %q", tt.input, i, v, tt.expected[i])
				}
			}
		})
	}
}

// ============================================================================
// parseDuration Tests
// ============================================================================

func TestParseDuration_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected config.Duration
	}{
		{
			name:     "seconds",
			input:    "30s",
			expected: config.Duration(30 * time.Second),
		},
		{
			name:     "minutes",
			input:    "5m",
			expected: config.Duration(5 * time.Minute),
		},
		{
			name:     "milliseconds",
			input:    "100ms",
			expected: config.Duration(100 * time.Millisecond),
		},
		{
			name:     "invalid duration",
			input:    "invalid",
			expected: 0,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDuration(tt.input)
			if result != tt.expected {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// Annotation Tests - Timeout
// ============================================================================

func TestConvertIngress_TimeoutAnnotation(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("timeout-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationTimeout: "30s",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Timeout != config.Duration(30*time.Second) {
			t.Errorf("Route timeout = %v, want 30s", route.Timeout)
		}
	}
}

// ============================================================================
// Annotation Tests - Retry
// ============================================================================

func TestConvertIngress_RetryAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("retry-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationRetryAttempts:      "3",
		AnnotationRetryPerTryTimeout: "5s",
		AnnotationRetryOn:            "5xx,reset",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Retries == nil {
			t.Fatal("Route retries should not be nil")
		}
		if route.Retries.Attempts != 3 {
			t.Errorf("Retry attempts = %d, want 3", route.Retries.Attempts)
		}
		if route.Retries.PerTryTimeout != config.Duration(5*time.Second) {
			t.Errorf("Retry per-try timeout = %v, want 5s", route.Retries.PerTryTimeout)
		}
		if route.Retries.RetryOn != "5xx,reset" {
			t.Errorf("Retry on = %q, want %q", route.Retries.RetryOn, "5xx,reset")
		}
	}
}

func TestConvertIngress_RetryAnnotations_NoRetryAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("no-retry", "default")

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Retries != nil {
			t.Error("Route retries should be nil when no retry annotations")
		}
	}
}

func TestConvertIngress_RetryAnnotations_InvalidAttempts(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("invalid-retry", "default")
	ingress.Annotations = map[string]string{
		AnnotationRetryAttempts: "invalid",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Retries == nil {
			t.Fatal("Route retries should not be nil (annotation was present)")
		}
		if route.Retries.Attempts != 0 {
			t.Errorf("Retry attempts = %d, want 0 (invalid parse)", route.Retries.Attempts)
		}
	}
}

// ============================================================================
// Annotation Tests - Rate Limit
// ============================================================================

func TestConvertIngress_RateLimitAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("ratelimit-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationRateLimitEnabled:   "true",
		AnnotationRateLimitRPS:       "100",
		AnnotationRateLimitBurst:     "10",
		AnnotationRateLimitPerClient: "true",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.RateLimit == nil {
			t.Fatal("Route rate limit should not be nil")
		}
		if !route.RateLimit.Enabled {
			t.Error("Rate limit should be enabled")
		}
		if route.RateLimit.RequestsPerSecond != 100 {
			t.Errorf("Rate limit RPS = %d, want 100", route.RateLimit.RequestsPerSecond)
		}
		if route.RateLimit.Burst != 10 {
			t.Errorf("Rate limit burst = %d, want 10", route.RateLimit.Burst)
		}
		if !route.RateLimit.PerClient {
			t.Error("Rate limit per-client should be true")
		}
	}
}

func TestConvertIngress_RateLimitAnnotations_NotEnabled(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("ratelimit-disabled", "default")
	// No rate limit annotations

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.RateLimit != nil {
			t.Error("Route rate limit should be nil when not enabled")
		}
	}
}

// ============================================================================
// Annotation Tests - CORS
// ============================================================================

func TestConvertIngress_CORSAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("cors-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationCORSAllowOrigins:     "https://example.com, https://other.com",
		AnnotationCORSAllowMethods:     "GET, POST, PUT",
		AnnotationCORSAllowHeaders:     "Content-Type, Authorization",
		AnnotationCORSExposeHeaders:    "X-Custom-Header",
		AnnotationCORSMaxAge:           "3600",
		AnnotationCORSAllowCredentials: "true",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.CORS == nil {
			t.Fatal("Route CORS should not be nil")
		}
		if len(route.CORS.AllowOrigins) != 2 {
			t.Errorf("CORS allow origins count = %d, want 2", len(route.CORS.AllowOrigins))
		}
		if len(route.CORS.AllowMethods) != 3 {
			t.Errorf("CORS allow methods count = %d, want 3", len(route.CORS.AllowMethods))
		}
		if len(route.CORS.AllowHeaders) != 2 {
			t.Errorf("CORS allow headers count = %d, want 2", len(route.CORS.AllowHeaders))
		}
		if len(route.CORS.ExposeHeaders) != 1 {
			t.Errorf("CORS expose headers count = %d, want 1", len(route.CORS.ExposeHeaders))
		}
		if route.CORS.MaxAge != 3600 {
			t.Errorf("CORS max age = %d, want 3600", route.CORS.MaxAge)
		}
		if !route.CORS.AllowCredentials {
			t.Error("CORS allow credentials should be true")
		}
	}
}

// ============================================================================
// Annotation Tests - Rewrite
// ============================================================================

func TestConvertIngress_RewriteAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("rewrite-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationRewriteURI:       "/new-path",
		AnnotationRewriteAuthority: "new-host.example.com",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Rewrite == nil {
			t.Fatal("Route rewrite should not be nil")
		}
		if route.Rewrite.URI != "/new-path" {
			t.Errorf("Rewrite URI = %q, want %q", route.Rewrite.URI, "/new-path")
		}
		if route.Rewrite.Authority != "new-host.example.com" {
			t.Errorf("Rewrite authority = %q, want %q", route.Rewrite.Authority, "new-host.example.com")
		}
	}
}

func TestConvertIngress_RewriteAnnotations_NoAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("no-rewrite", "default")

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Rewrite != nil {
			t.Error("Route rewrite should be nil when no annotations")
		}
	}
}

// ============================================================================
// Annotation Tests - Redirect
// ============================================================================

func TestConvertIngress_RedirectAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("redirect-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationRedirectURI:    "/new-location",
		AnnotationRedirectCode:   "301",
		AnnotationRedirectScheme: "https",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Redirect == nil {
			t.Fatal("Route redirect should not be nil")
		}
		if route.Redirect.URI != "/new-location" {
			t.Errorf("Redirect URI = %q, want %q", route.Redirect.URI, "/new-location")
		}
		if route.Redirect.Code != 301 {
			t.Errorf("Redirect code = %d, want 301", route.Redirect.Code)
		}
		if route.Redirect.Scheme != "https" {
			t.Errorf("Redirect scheme = %q, want %q", route.Redirect.Scheme, "https")
		}
	}
}

// ============================================================================
// Annotation Tests - Security
// ============================================================================

func TestConvertIngress_SecurityAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("security-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationSecurityEnabled:        "true",
		AnnotationSecurityXFrameOptions:  "DENY",
		AnnotationSecurityXContentType:   "nosniff",
		AnnotationSecurityXXSSProtection: "1; mode=block",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Security == nil {
			t.Fatal("Route security should not be nil")
		}
		if !route.Security.Enabled {
			t.Error("Security should be enabled")
		}
		if route.Security.Headers == nil {
			t.Fatal("Security headers should not be nil")
		}
		if !route.Security.Headers.Enabled {
			t.Error("Security headers should be enabled")
		}
		if route.Security.Headers.XFrameOptions != "DENY" {
			t.Errorf("X-Frame-Options = %q, want %q", route.Security.Headers.XFrameOptions, "DENY")
		}
		if route.Security.Headers.XContentTypeOptions != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want %q", route.Security.Headers.XContentTypeOptions, "nosniff")
		}
		if route.Security.Headers.XXSSProtection != "1; mode=block" {
			t.Errorf("X-XSS-Protection = %q, want %q", route.Security.Headers.XXSSProtection, "1; mode=block")
		}
	}
}

func TestConvertIngress_SecurityAnnotations_EnabledOnly(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("security-enabled-only", "default")
	ingress.Annotations = map[string]string{
		AnnotationSecurityEnabled: "true",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Security == nil {
			t.Fatal("Route security should not be nil")
		}
		if route.Security.Headers != nil {
			t.Error("Security headers should be nil when no header annotations")
		}
	}
}

// ============================================================================
// Annotation Tests - Encoding
// ============================================================================

func TestConvertIngress_EncodingAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("encoding-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationEncodingRequestContentType:  "application/json",
		AnnotationEncodingResponseContentType: "application/xml",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Encoding == nil {
			t.Fatal("Route encoding should not be nil")
		}
		if route.Encoding.RequestEncoding != "application/json" {
			t.Errorf("Request encoding = %q, want %q", route.Encoding.RequestEncoding, "application/json")
		}
		if route.Encoding.ResponseEncoding != "application/xml" {
			t.Errorf("Response encoding = %q, want %q", route.Encoding.ResponseEncoding, "application/xml")
		}
	}
}

// ============================================================================
// Annotation Tests - Cache
// ============================================================================

func TestConvertIngress_CacheAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("cache-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationCacheEnabled: "true",
		AnnotationCacheTTL:     "5m",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.Cache == nil {
			t.Fatal("Route cache should not be nil")
		}
		if !route.Cache.Enabled {
			t.Error("Cache should be enabled")
		}
		if route.Cache.TTL != config.Duration(5*time.Minute) {
			t.Errorf("Cache TTL = %v, want 5m", route.Cache.TTL)
		}
	}
}

// ============================================================================
// Annotation Tests - Max Sessions
// ============================================================================

func TestConvertIngress_MaxSessionsAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("maxsessions-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationMaxSessionsEnabled:       "true",
		AnnotationMaxSessionsMaxConcurrent: "100",
		AnnotationMaxSessionsQueueSize:     "50",
		AnnotationMaxSessionsQueueTimeout:  "10s",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.MaxSessions == nil {
			t.Fatal("Route max sessions should not be nil")
		}
		if !route.MaxSessions.Enabled {
			t.Error("Max sessions should be enabled")
		}
		if route.MaxSessions.MaxConcurrent != 100 {
			t.Errorf("Max concurrent = %d, want 100", route.MaxSessions.MaxConcurrent)
		}
		if route.MaxSessions.QueueSize != 50 {
			t.Errorf("Queue size = %d, want 50", route.MaxSessions.QueueSize)
		}
		if route.MaxSessions.QueueTimeout != config.Duration(10*time.Second) {
			t.Errorf("Queue timeout = %v, want 10s", route.MaxSessions.QueueTimeout)
		}
	}
}

// ============================================================================
// Annotation Tests - Max Body Size
// ============================================================================

func TestConvertIngress_MaxBodySizeAnnotation(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("maxbody-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationMaxBodySize: "1048576",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.RequestLimits == nil {
			t.Fatal("Route request limits should not be nil")
		}
		if route.RequestLimits.MaxBodySize != 1048576 {
			t.Errorf("Max body size = %d, want 1048576", route.RequestLimits.MaxBodySize)
		}
	}
}

func TestConvertIngress_MaxBodySizeAnnotation_Invalid(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("maxbody-invalid", "default")
	ingress.Annotations = map[string]string{
		AnnotationMaxBodySize: "invalid",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, routeJSON := range result.Routes {
		var route config.Route
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal route: %v", err)
		}
		if route.RequestLimits != nil {
			t.Error("Route request limits should be nil for invalid value")
		}
	}
}

// ============================================================================
// Backend Annotation Tests - Health Check
// ============================================================================

func TestConvertIngress_HealthCheckAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("healthcheck-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationHealthCheckPath:               "/health",
		AnnotationHealthCheckInterval:           "10s",
		AnnotationHealthCheckTimeout:            "5s",
		AnnotationHealthCheckHealthyThreshold:   "3",
		AnnotationHealthCheckUnhealthyThreshold: "2",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, backendJSON := range result.Backends {
		var backend config.Backend
		if err := json.Unmarshal(backendJSON, &backend); err != nil {
			t.Fatalf("Failed to unmarshal backend: %v", err)
		}
		if backend.HealthCheck == nil {
			t.Fatal("Backend health check should not be nil")
		}
		if backend.HealthCheck.Path != "/health" {
			t.Errorf("Health check path = %q, want %q", backend.HealthCheck.Path, "/health")
		}
		if backend.HealthCheck.Interval != config.Duration(10*time.Second) {
			t.Errorf("Health check interval = %v, want 10s", backend.HealthCheck.Interval)
		}
		if backend.HealthCheck.Timeout != config.Duration(5*time.Second) {
			t.Errorf("Health check timeout = %v, want 5s", backend.HealthCheck.Timeout)
		}
		if backend.HealthCheck.HealthyThreshold != 3 {
			t.Errorf("Healthy threshold = %d, want 3", backend.HealthCheck.HealthyThreshold)
		}
		if backend.HealthCheck.UnhealthyThreshold != 2 {
			t.Errorf("Unhealthy threshold = %d, want 2", backend.HealthCheck.UnhealthyThreshold)
		}
	}
}

// ============================================================================
// Backend Annotation Tests - Load Balancer
// ============================================================================

func TestConvertIngress_LoadBalancerAnnotation(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("lb-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationLoadBalancerAlgorithm: "round-robin",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, backendJSON := range result.Backends {
		var backend config.Backend
		if err := json.Unmarshal(backendJSON, &backend); err != nil {
			t.Fatalf("Failed to unmarshal backend: %v", err)
		}
		if backend.LoadBalancer == nil {
			t.Fatal("Backend load balancer should not be nil")
		}
		if backend.LoadBalancer.Algorithm != "round-robin" {
			t.Errorf("LB algorithm = %q, want %q", backend.LoadBalancer.Algorithm, "round-robin")
		}
	}
}

// ============================================================================
// Backend Annotation Tests - Circuit Breaker
// ============================================================================

func TestConvertIngress_CircuitBreakerAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestIngress("cb-test", "default")
	ingress.Annotations = map[string]string{
		AnnotationCircuitBreakerEnabled:   "true",
		AnnotationCircuitBreakerThreshold: "5",
		AnnotationCircuitBreakerTimeout:   "30s",
		AnnotationCircuitBreakerHalfOpen:  "3",
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	for _, backendJSON := range result.Backends {
		var backend config.Backend
		if err := json.Unmarshal(backendJSON, &backend); err != nil {
			t.Fatalf("Failed to unmarshal backend: %v", err)
		}
		if backend.CircuitBreaker == nil {
			t.Fatal("Backend circuit breaker should not be nil")
		}
		if !backend.CircuitBreaker.Enabled {
			t.Error("Circuit breaker should be enabled")
		}
		if backend.CircuitBreaker.Threshold != 5 {
			t.Errorf("CB threshold = %d, want 5", backend.CircuitBreaker.Threshold)
		}
		if backend.CircuitBreaker.Timeout != config.Duration(30*time.Second) {
			t.Errorf("CB timeout = %v, want 30s", backend.CircuitBreaker.Timeout)
		}
		if backend.CircuitBreaker.HalfOpenRequests != 3 {
			t.Errorf("CB half-open = %d, want 3", backend.CircuitBreaker.HalfOpenRequests)
		}
	}
}

// ============================================================================
// TLS Annotations Tests
// ============================================================================

func TestApplyTLSAnnotations_NilTLS(t *testing.T) {
	converter := NewIngressConverter()
	route := &config.Route{}
	annotations := map[string]string{
		AnnotationTLSMinVersion: "TLS12",
	}

	converter.applyTLSAnnotations(route, annotations)
	// Should not panic and TLS should remain nil
	if route.TLS != nil {
		t.Error("TLS should remain nil when route.TLS is nil")
	}
}

// ============================================================================
// Ingress Constants Tests
// ============================================================================

func TestIngressConstants(t *testing.T) {
	if IngressControllerName == "" {
		t.Error("IngressControllerName should not be empty")
	}
	if DefaultIngressClassName == "" {
		t.Error("DefaultIngressClassName should not be empty")
	}
	if IngressFinalizerName == "" {
		t.Error("IngressFinalizerName should not be empty")
	}
	if AnnotationPrefix == "" {
		t.Error("AnnotationPrefix should not be empty")
	}
	if AnnotationIngressClass == "" {
		t.Error("AnnotationIngressClass should not be empty")
	}
}

func TestEventReasonConstants(t *testing.T) {
	if EventReasonIngressReconciled == "" {
		t.Error("EventReasonIngressReconciled should not be empty")
	}
	if EventReasonIngressReconcileFailed == "" {
		t.Error("EventReasonIngressReconcileFailed should not be empty")
	}
	if EventReasonIngressDeleted == "" {
		t.Error("EventReasonIngressDeleted should not be empty")
	}
	if EventReasonIngressCleanupFailed == "" {
		t.Error("EventReasonIngressCleanupFailed should not be empty")
	}
	if EventReasonIngressClassMismatch == "" {
		t.Error("EventReasonIngressClassMismatch should not be empty")
	}
	if EventReasonIngressConversionFailed == "" {
		t.Error("EventReasonIngressConversionFailed should not be empty")
	}
}

func TestStatusMessageConstants(t *testing.T) {
	if MessageIngressApplied == "" {
		t.Error("MessageIngressApplied should not be empty")
	}
	if MessageIngressDeleted == "" {
		t.Error("MessageIngressDeleted should not be empty")
	}
	if MessageIngressConversionFailed == "" {
		t.Error("MessageIngressConversionFailed should not be empty")
	}
}

// ============================================================================
// gRPC Protocol Detection Tests
// ============================================================================

func TestIsGRPCIngress_TableDriven(t *testing.T) {
	converter := NewIngressConverter()

	tests := []struct {
		name        string
		annotations map[string]string
		expected    bool
	}{
		{
			name:        "nil annotations",
			annotations: nil,
			expected:    false,
		},
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			expected:    false,
		},
		{
			name: "no protocol annotation",
			annotations: map[string]string{
				"other": "value",
			},
			expected: false,
		},
		{
			name: "http protocol",
			annotations: map[string]string{
				AnnotationProtocol: "http",
			},
			expected: false,
		},
		{
			name: "grpc protocol lowercase",
			annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
			expected: true,
		},
		{
			name: "grpc protocol uppercase",
			annotations: map[string]string{
				AnnotationProtocol: "GRPC",
			},
			expected: true,
		},
		{
			name: "grpc protocol mixed case",
			annotations: map[string]string{
				AnnotationProtocol: "GrPc",
			},
			expected: true,
		},
		{
			name: "h2c protocol",
			annotations: map[string]string{
				AnnotationProtocol: "h2c",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.isGRPCIngress(tt.annotations)
			if result != tt.expected {
				t.Errorf("isGRPCIngress() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetProtocol_TableDriven(t *testing.T) {
	converter := NewIngressConverter()

	tests := []struct {
		name        string
		annotations map[string]string
		expected    string
	}{
		{
			name:        "nil annotations",
			annotations: nil,
			expected:    ProtocolHTTP,
		},
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			expected:    ProtocolHTTP,
		},
		{
			name: "no protocol annotation",
			annotations: map[string]string{
				"other": "value",
			},
			expected: ProtocolHTTP,
		},
		{
			name: "http protocol",
			annotations: map[string]string{
				AnnotationProtocol: "http",
			},
			expected: "http",
		},
		{
			name: "grpc protocol",
			annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
			expected: "grpc",
		},
		{
			name: "GRPC protocol uppercase",
			annotations: map[string]string{
				AnnotationProtocol: "GRPC",
			},
			expected: "grpc",
		},
		{
			name: "h2c protocol",
			annotations: map[string]string{
				AnnotationProtocol: "H2C",
			},
			expected: "h2c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.getProtocol(tt.annotations)
			if result != tt.expected {
				t.Errorf("getProtocol() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// ============================================================================
// buildStringMatch Tests
// ============================================================================

func TestBuildStringMatch_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		matchType  string
		wantNil    bool
		wantExact  string
		wantPrefix string
		wantRegex  string
	}{
		{
			name:    "empty value returns nil",
			value:   "",
			wantNil: true,
		},
		{
			name:      "exact match type",
			value:     "api.v1.UserService",
			matchType: MatchTypeExact,
			wantExact: "api.v1.UserService",
		},
		{
			name:       "prefix match type",
			value:      "api.v1",
			matchType:  MatchTypePrefix,
			wantPrefix: "api.v1",
		},
		{
			name:      "regex match type",
			value:     "api\\.v[0-9]+\\..*",
			matchType: MatchTypeRegex,
			wantRegex: "api\\.v[0-9]+\\..*",
		},
		{
			name:       "default match type is prefix",
			value:      "api.v1",
			matchType:  "",
			wantPrefix: "api.v1",
		},
		{
			name:       "unknown match type defaults to prefix",
			value:      "api.v1",
			matchType:  "unknown",
			wantPrefix: "api.v1",
		},
		{
			name:      "EXACT uppercase",
			value:     "api.v1.UserService",
			matchType: "EXACT",
			wantExact: "api.v1.UserService",
		},
		{
			name:       "Prefix mixed case",
			value:      "api.v1",
			matchType:  "Prefix",
			wantPrefix: "api.v1",
		},
		{
			name:      "REGEX uppercase",
			value:     ".*Service",
			matchType: "REGEX",
			wantRegex: ".*Service",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildStringMatch(tt.value, tt.matchType)
			if tt.wantNil {
				if result != nil {
					t.Error("buildStringMatch() should return nil")
				}
				return
			}
			if result == nil {
				t.Fatal("buildStringMatch() returned nil")
			}
			if tt.wantExact != "" && result.Exact != tt.wantExact {
				t.Errorf("buildStringMatch() Exact = %q, want %q", result.Exact, tt.wantExact)
			}
			if tt.wantPrefix != "" && result.Prefix != tt.wantPrefix {
				t.Errorf("buildStringMatch() Prefix = %q, want %q", result.Prefix, tt.wantPrefix)
			}
			if tt.wantRegex != "" && result.Regex != tt.wantRegex {
				t.Errorf("buildStringMatch() Regex = %q, want %q", result.Regex, tt.wantRegex)
			}
		})
	}
}

// ============================================================================
// buildGRPCRouteMatch Tests
// ============================================================================

func TestBuildGRPCRouteMatch_TableDriven(t *testing.T) {
	converter := NewIngressConverter()

	tests := []struct {
		name            string
		host            string
		path            networkingv1.HTTPIngressPath
		annotations     map[string]string
		wantAuthority   string
		wantService     string
		wantServiceType string
		wantMethod      string
		wantMethodType  string
	}{
		{
			name: "empty host and path",
			host: "",
			path: networkingv1.HTTPIngressPath{
				Path: "",
			},
			annotations: map[string]string{},
		},
		{
			name: "host sets authority",
			host: "grpc.example.com",
			path: networkingv1.HTTPIngressPath{
				Path: "",
			},
			annotations:   map[string]string{},
			wantAuthority: "grpc.example.com",
		},
		{
			name: "path sets service prefix",
			host: "",
			path: networkingv1.HTTPIngressPath{
				Path: "/api.v1.UserService",
			},
			annotations:     map[string]string{},
			wantService:     "api.v1.UserService",
			wantServiceType: "prefix",
		},
		{
			name: "explicit service annotation",
			host: "",
			path: networkingv1.HTTPIngressPath{
				Path: "/ignored",
			},
			annotations: map[string]string{
				AnnotationGRPCService:          "api.v1.UserService",
				AnnotationGRPCServiceMatchType: "exact",
			},
			wantService:     "api.v1.UserService",
			wantServiceType: "exact",
		},
		{
			name: "method annotation",
			host: "",
			path: networkingv1.HTTPIngressPath{
				Path: "",
			},
			annotations: map[string]string{
				AnnotationGRPCMethod:          "GetUser",
				AnnotationGRPCMethodMatchType: "exact",
			},
			wantMethod:     "GetUser",
			wantMethodType: "exact",
		},
		{
			name: "full match with all fields",
			host: "grpc.example.com",
			path: networkingv1.HTTPIngressPath{
				Path: "/api.v1",
			},
			annotations: map[string]string{
				AnnotationGRPCService:          "api.v1.UserService",
				AnnotationGRPCServiceMatchType: "exact",
				AnnotationGRPCMethod:           "Get.*",
				AnnotationGRPCMethodMatchType:  "regex",
			},
			wantAuthority:   "grpc.example.com",
			wantService:     "api.v1.UserService",
			wantServiceType: "exact",
			wantMethod:      "Get.*",
			wantMethodType:  "regex",
		},
		{
			name: "root path does not set service",
			host: "",
			path: networkingv1.HTTPIngressPath{
				Path: "/",
			},
			annotations: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := converter.buildGRPCRouteMatch(tt.host, tt.path, tt.annotations)

			// Check authority
			if tt.wantAuthority != "" {
				if result.Authority == nil {
					t.Fatal("Authority should not be nil")
				}
				if result.Authority.Exact != tt.wantAuthority {
					t.Errorf("Authority.Exact = %q, want %q", result.Authority.Exact, tt.wantAuthority)
				}
			} else if result.Authority != nil {
				t.Error("Authority should be nil")
			}

			// Check service
			if tt.wantService != "" {
				if result.Service == nil {
					t.Fatal("Service should not be nil")
				}
				switch tt.wantServiceType {
				case "exact":
					if result.Service.Exact != tt.wantService {
						t.Errorf("Service.Exact = %q, want %q", result.Service.Exact, tt.wantService)
					}
				case "prefix":
					if result.Service.Prefix != tt.wantService {
						t.Errorf("Service.Prefix = %q, want %q", result.Service.Prefix, tt.wantService)
					}
				case "regex":
					if result.Service.Regex != tt.wantService {
						t.Errorf("Service.Regex = %q, want %q", result.Service.Regex, tt.wantService)
					}
				}
			}

			// Check method
			if tt.wantMethod != "" {
				if result.Method == nil {
					t.Fatal("Method should not be nil")
				}
				switch tt.wantMethodType {
				case "exact":
					if result.Method.Exact != tt.wantMethod {
						t.Errorf("Method.Exact = %q, want %q", result.Method.Exact, tt.wantMethod)
					}
				case "prefix":
					if result.Method.Prefix != tt.wantMethod {
						t.Errorf("Method.Prefix = %q, want %q", result.Method.Prefix, tt.wantMethod)
					}
				case "regex":
					if result.Method.Regex != tt.wantMethod {
						t.Errorf("Method.Regex = %q, want %q", result.Method.Regex, tt.wantMethod)
					}
				}
			}
		})
	}
}

// ============================================================================
// buildGRPCRoute Tests
// ============================================================================

func TestBuildGRPCRoute_Basic(t *testing.T) {
	converter := NewIngressConverter()
	path := networkingv1.HTTPIngressPath{
		Path:     "/api.v1.UserService",
		PathType: ptrPathType(networkingv1.PathTypePrefix),
		Backend: networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "user-service",
				Port: networkingv1.ServiceBackendPort{Number: 50051},
			},
		},
	}
	annotations := map[string]string{
		AnnotationProtocol: "grpc",
	}
	tlsHosts := map[string]bool{}

	route, err := converter.buildGRPCRoute("test-route", "grpc.example.com", path, annotations, tlsHosts)
	if err != nil {
		t.Fatalf("buildGRPCRoute() error = %v", err)
	}

	if route.Name != "test-route" {
		t.Errorf("Route name = %q, want %q", route.Name, "test-route")
	}
	if len(route.Match) != 1 {
		t.Fatalf("Route match count = %d, want 1", len(route.Match))
	}
	if route.Match[0].Authority == nil || route.Match[0].Authority.Exact != "grpc.example.com" {
		t.Error("Route should have authority match")
	}
	if len(route.Route) != 1 {
		t.Fatalf("Route destinations = %d, want 1", len(route.Route))
	}
	if route.Route[0].Destination.Host != "user-service" {
		t.Errorf("Destination host = %q, want %q", route.Route[0].Destination.Host, "user-service")
	}
	if route.Route[0].Destination.Port != 50051 {
		t.Errorf("Destination port = %d, want %d", route.Route[0].Destination.Port, 50051)
	}
	if route.Route[0].Weight != 100 {
		t.Errorf("Destination weight = %d, want %d", route.Route[0].Weight, 100)
	}
}

func TestBuildGRPCRoute_WithTLS(t *testing.T) {
	converter := NewIngressConverter()
	path := networkingv1.HTTPIngressPath{
		Path: "/api.v1",
		Backend: networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: "grpc-service",
				Port: networkingv1.ServiceBackendPort{Number: 443},
			},
		},
	}
	annotations := map[string]string{
		AnnotationProtocol:      "grpc",
		AnnotationTLSMinVersion: "TLS12",
		AnnotationTLSMaxVersion: "TLS13",
	}
	tlsHosts := map[string]bool{
		"secure.grpc.example.com": true,
	}

	route, err := converter.buildGRPCRoute("tls-route", "secure.grpc.example.com", path, annotations, tlsHosts)
	if err != nil {
		t.Fatalf("buildGRPCRoute() error = %v", err)
	}

	if route.TLS == nil {
		t.Fatal("Route TLS should not be nil")
	}
	if len(route.TLS.SNIHosts) != 1 || route.TLS.SNIHosts[0] != "secure.grpc.example.com" {
		t.Errorf("TLS SNIHosts = %v, want [secure.grpc.example.com]", route.TLS.SNIHosts)
	}
	if route.TLS.MinVersion != "TLS12" {
		t.Errorf("TLS MinVersion = %q, want %q", route.TLS.MinVersion, "TLS12")
	}
	if route.TLS.MaxVersion != "TLS13" {
		t.Errorf("TLS MaxVersion = %q, want %q", route.TLS.MaxVersion, "TLS13")
	}
}

func TestBuildGRPCRoute_NoServiceBackend(t *testing.T) {
	converter := NewIngressConverter()
	path := networkingv1.HTTPIngressPath{
		Path:    "/api.v1",
		Backend: networkingv1.IngressBackend{},
	}
	annotations := map[string]string{}
	tlsHosts := map[string]bool{}

	_, err := converter.buildGRPCRoute("test-route", "", path, annotations, tlsHosts)
	if err == nil {
		t.Error("buildGRPCRoute() should return error for no service backend")
	}
}

// ============================================================================
// buildGRPCDefaultRoute Tests
// ============================================================================

func TestBuildGRPCDefaultRoute(t *testing.T) {
	converter := NewIngressConverter()
	annotations := map[string]string{
		AnnotationTimeout: "30s",
	}
	backend := networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "default-svc",
			Port: networkingv1.ServiceBackendPort{Number: 8080},
		},
	}

	route, err := converter.buildGRPCDefaultRoute("default-grpc-route", backend, annotations)
	if err != nil {
		t.Fatalf("buildGRPCDefaultRoute() error = %v", err)
	}

	if route.Name != "default-grpc-route" {
		t.Errorf("Route name = %q, want %q", route.Name, "default-grpc-route")
	}
	if len(route.Match) != 1 {
		t.Fatalf("Route match count = %d, want 1", len(route.Match))
	}
	if route.Match[0].Service == nil {
		t.Fatal("Default route should have service match")
	}
	if route.Match[0].Service.Prefix != "" {
		t.Errorf("Default route service prefix = %q, want empty (catch-all)", route.Match[0].Service.Prefix)
	}
	if route.Timeout != config.Duration(30*time.Second) {
		t.Errorf("Route timeout = %v, want 30s", route.Timeout)
	}
	// Verify route destination is set (BUG-1 fix)
	if len(route.Route) != 1 {
		t.Fatalf("Route destinations count = %d, want 1", len(route.Route))
	}
	if route.Route[0].Destination.Host != "default-svc" {
		t.Errorf("Route destination host = %q, want %q", route.Route[0].Destination.Host, "default-svc")
	}
	if route.Route[0].Destination.Port != 8080 {
		t.Errorf("Route destination port = %d, want 8080", route.Route[0].Destination.Port)
	}
}

// ============================================================================
// buildGRPCBackend Tests
// ============================================================================

func TestBuildGRPCBackend_Basic(t *testing.T) {
	converter := NewIngressConverter()
	backend := networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "grpc-service",
			Port: networkingv1.ServiceBackendPort{Number: 50051},
		},
	}
	annotations := map[string]string{}

	result := converter.buildGRPCBackend("test-backend", backend, annotations)

	if result.Name != "test-backend" {
		t.Errorf("Backend name = %q, want %q", result.Name, "test-backend")
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("Backend hosts count = %d, want 1", len(result.Hosts))
	}
	if result.Hosts[0].Address != "grpc-service" {
		t.Errorf("Host address = %q, want %q", result.Hosts[0].Address, "grpc-service")
	}
	if result.Hosts[0].Port != 50051 {
		t.Errorf("Host port = %d, want %d", result.Hosts[0].Port, 50051)
	}
	if result.Hosts[0].Weight != 1 {
		t.Errorf("Host weight = %d, want %d", result.Hosts[0].Weight, 1)
	}
}

func TestBuildGRPCBackend_NoService(t *testing.T) {
	converter := NewIngressConverter()
	backend := networkingv1.IngressBackend{}
	annotations := map[string]string{}

	result := converter.buildGRPCBackend("test-backend", backend, annotations)

	if result.Name != "test-backend" {
		t.Errorf("Backend name = %q, want %q", result.Name, "test-backend")
	}
	if len(result.Hosts) != 0 {
		t.Errorf("Backend hosts count = %d, want 0", len(result.Hosts))
	}
}

// ============================================================================
// applyGRPCRouteAnnotations Tests
// ============================================================================

func TestApplyGRPCRouteAnnotations_Timeout(t *testing.T) {
	converter := NewIngressConverter()
	route := &config.GRPCRoute{Name: "test"}
	annotations := map[string]string{
		AnnotationTimeout: "45s",
	}

	converter.applyGRPCRouteAnnotations(route, annotations)

	if route.Timeout != config.Duration(45*time.Second) {
		t.Errorf("Route timeout = %v, want 45s", route.Timeout)
	}
}

func TestApplyGRPCRouteAnnotations_AllAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	route := &config.GRPCRoute{Name: "test"}
	annotations := map[string]string{
		AnnotationTimeout:                     "30s",
		AnnotationRetryAttempts:               "3",
		AnnotationRetryPerTryTimeout:          "5s",
		AnnotationGRPCRetryOn:                 "unavailable,resource-exhausted",
		AnnotationGRPCBackoffBaseInterval:     "100ms",
		AnnotationGRPCBackoffMaxInterval:      "1s",
		AnnotationRateLimitEnabled:            "true",
		AnnotationRateLimitRPS:                "100",
		AnnotationCORSAllowOrigins:            "https://example.com",
		AnnotationSecurityEnabled:             "true",
		AnnotationEncodingRequestContentType:  "application/grpc",
		AnnotationEncodingResponseContentType: "application/grpc",
		AnnotationCacheEnabled:                "true",
		AnnotationCacheTTL:                    "5m",
	}

	converter.applyGRPCRouteAnnotations(route, annotations)

	if route.Timeout != config.Duration(30*time.Second) {
		t.Errorf("Timeout = %v, want 30s", route.Timeout)
	}
	if route.Retries == nil {
		t.Fatal("Retries should not be nil")
	}
	if route.RateLimit == nil {
		t.Fatal("RateLimit should not be nil")
	}
	if route.CORS == nil {
		t.Fatal("CORS should not be nil")
	}
	if route.Security == nil {
		t.Fatal("Security should not be nil")
	}
	if route.Encoding == nil {
		t.Fatal("Encoding should not be nil")
	}
	if route.Cache == nil {
		t.Fatal("Cache should not be nil")
	}
}

// ============================================================================
// applyGRPCRetryAnnotations Tests
// ============================================================================

func TestApplyGRPCRetryAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name                    string
		annotations             map[string]string
		wantNil                 bool
		wantAttempts            int
		wantPerTryTimeout       config.Duration
		wantRetryOn             string
		wantBackoffBaseInterval config.Duration
		wantBackoffMaxInterval  config.Duration
	}{
		{
			name:        "no retry annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "only attempts",
			annotations: map[string]string{
				AnnotationRetryAttempts: "3",
			},
			wantAttempts: 3,
		},
		{
			name: "gRPC retry on",
			annotations: map[string]string{
				AnnotationGRPCRetryOn: "unavailable,resource-exhausted",
			},
			wantRetryOn: "unavailable,resource-exhausted",
		},
		{
			name: "fallback to standard retry on",
			annotations: map[string]string{
				AnnotationRetryOn: "5xx",
			},
			wantRetryOn: "5xx",
		},
		{
			name: "gRPC retry on takes precedence",
			annotations: map[string]string{
				AnnotationRetryOn:     "5xx",
				AnnotationGRPCRetryOn: "unavailable",
			},
			wantRetryOn: "unavailable",
		},
		{
			name: "full retry config",
			annotations: map[string]string{
				AnnotationRetryAttempts:           "5",
				AnnotationRetryPerTryTimeout:      "10s",
				AnnotationGRPCRetryOn:             "unavailable,internal",
				AnnotationGRPCBackoffBaseInterval: "200ms",
				AnnotationGRPCBackoffMaxInterval:  "2s",
			},
			wantAttempts:            5,
			wantPerTryTimeout:       config.Duration(10 * time.Second),
			wantRetryOn:             "unavailable,internal",
			wantBackoffBaseInterval: config.Duration(200 * time.Millisecond),
			wantBackoffMaxInterval:  config.Duration(2 * time.Second),
		},
		{
			name: "invalid attempts value",
			annotations: map[string]string{
				AnnotationRetryAttempts: "invalid",
			},
			wantAttempts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test"}

			converter.applyGRPCRetryAnnotations(route, tt.annotations)

			if tt.wantNil {
				if route.Retries != nil {
					t.Error("Retries should be nil")
				}
				return
			}

			if route.Retries == nil {
				t.Fatal("Retries should not be nil")
			}
			if route.Retries.Attempts != tt.wantAttempts {
				t.Errorf("Attempts = %d, want %d", route.Retries.Attempts, tt.wantAttempts)
			}
			if route.Retries.PerTryTimeout != tt.wantPerTryTimeout {
				t.Errorf("PerTryTimeout = %v, want %v", route.Retries.PerTryTimeout, tt.wantPerTryTimeout)
			}
			if route.Retries.RetryOn != tt.wantRetryOn {
				t.Errorf("RetryOn = %q, want %q", route.Retries.RetryOn, tt.wantRetryOn)
			}
			if route.Retries.BackoffBaseInterval != tt.wantBackoffBaseInterval {
				t.Errorf("BackoffBaseInterval = %v, want %v", route.Retries.BackoffBaseInterval, tt.wantBackoffBaseInterval)
			}
			if route.Retries.BackoffMaxInterval != tt.wantBackoffMaxInterval {
				t.Errorf("BackoffMaxInterval = %v, want %v", route.Retries.BackoffMaxInterval, tt.wantBackoffMaxInterval)
			}
		})
	}
}

// ============================================================================
// applyGRPCRateLimitAnnotations Tests
// ============================================================================

func TestApplyGRPCRateLimitAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantNil     bool
		wantEnabled bool
		wantRPS     int
		wantBurst   int
		wantPerCli  bool
	}{
		{
			name:        "no rate limit annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "enabled only",
			annotations: map[string]string{
				AnnotationRateLimitEnabled: "true",
			},
			wantEnabled: true,
		},
		{
			name: "disabled",
			annotations: map[string]string{
				AnnotationRateLimitEnabled: "false",
			},
			wantEnabled: false,
		},
		{
			name: "full config",
			annotations: map[string]string{
				AnnotationRateLimitEnabled:   "true",
				AnnotationRateLimitRPS:       "1000",
				AnnotationRateLimitBurst:     "100",
				AnnotationRateLimitPerClient: "true",
			},
			wantEnabled: true,
			wantRPS:     1000,
			wantBurst:   100,
			wantPerCli:  true,
		},
		{
			name: "invalid RPS",
			annotations: map[string]string{
				AnnotationRateLimitEnabled: "true",
				AnnotationRateLimitRPS:     "invalid",
			},
			wantEnabled: true,
			wantRPS:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test"}

			converter.applyGRPCRateLimitAnnotations(route, tt.annotations)

			if tt.wantNil {
				if route.RateLimit != nil {
					t.Error("RateLimit should be nil")
				}
				return
			}

			if route.RateLimit == nil {
				t.Fatal("RateLimit should not be nil")
			}
			if route.RateLimit.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", route.RateLimit.Enabled, tt.wantEnabled)
			}
			if route.RateLimit.RequestsPerSecond != tt.wantRPS {
				t.Errorf("RPS = %d, want %d", route.RateLimit.RequestsPerSecond, tt.wantRPS)
			}
			if route.RateLimit.Burst != tt.wantBurst {
				t.Errorf("Burst = %d, want %d", route.RateLimit.Burst, tt.wantBurst)
			}
			if route.RateLimit.PerClient != tt.wantPerCli {
				t.Errorf("PerClient = %v, want %v", route.RateLimit.PerClient, tt.wantPerCli)
			}
		})
	}
}

// ============================================================================
// applyGRPCCORSAnnotations Tests
// ============================================================================

func TestApplyGRPCCORSAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name             string
		annotations      map[string]string
		wantNil          bool
		wantOriginsCount int
		wantMethodsCount int
		wantHeadersCount int
		wantExposeCount  int
		wantMaxAge       int
		wantAllowCreds   bool
	}{
		{
			name:        "no CORS annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "origins only",
			annotations: map[string]string{
				AnnotationCORSAllowOrigins: "https://example.com",
			},
			wantOriginsCount: 1,
		},
		{
			name: "full CORS config",
			annotations: map[string]string{
				AnnotationCORSAllowOrigins:     "https://a.com, https://b.com",
				AnnotationCORSAllowMethods:     "GET, POST, PUT",
				AnnotationCORSAllowHeaders:     "Content-Type, Authorization",
				AnnotationCORSExposeHeaders:    "X-Custom",
				AnnotationCORSMaxAge:           "7200",
				AnnotationCORSAllowCredentials: "true",
			},
			wantOriginsCount: 2,
			wantMethodsCount: 3,
			wantHeadersCount: 2,
			wantExposeCount:  1,
			wantMaxAge:       7200,
			wantAllowCreds:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test"}

			converter.applyGRPCCORSAnnotations(route, tt.annotations)

			if tt.wantNil {
				if route.CORS != nil {
					t.Error("CORS should be nil")
				}
				return
			}

			if route.CORS == nil {
				t.Fatal("CORS should not be nil")
			}
			if len(route.CORS.AllowOrigins) != tt.wantOriginsCount {
				t.Errorf("AllowOrigins count = %d, want %d", len(route.CORS.AllowOrigins), tt.wantOriginsCount)
			}
			if len(route.CORS.AllowMethods) != tt.wantMethodsCount {
				t.Errorf("AllowMethods count = %d, want %d", len(route.CORS.AllowMethods), tt.wantMethodsCount)
			}
			if len(route.CORS.AllowHeaders) != tt.wantHeadersCount {
				t.Errorf("AllowHeaders count = %d, want %d", len(route.CORS.AllowHeaders), tt.wantHeadersCount)
			}
			if len(route.CORS.ExposeHeaders) != tt.wantExposeCount {
				t.Errorf("ExposeHeaders count = %d, want %d", len(route.CORS.ExposeHeaders), tt.wantExposeCount)
			}
			if route.CORS.MaxAge != tt.wantMaxAge {
				t.Errorf("MaxAge = %d, want %d", route.CORS.MaxAge, tt.wantMaxAge)
			}
			if route.CORS.AllowCredentials != tt.wantAllowCreds {
				t.Errorf("AllowCredentials = %v, want %v", route.CORS.AllowCredentials, tt.wantAllowCreds)
			}
		})
	}
}

// ============================================================================
// applyGRPCSecurityAnnotations Tests
// ============================================================================

func TestApplyGRPCSecurityAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name         string
		annotations  map[string]string
		wantNil      bool
		wantEnabled  bool
		wantHeaders  bool
		wantXFrame   string
		wantXContent string
		wantXXSS     string
	}{
		{
			name:        "no security annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "enabled only",
			annotations: map[string]string{
				AnnotationSecurityEnabled: "true",
			},
			wantEnabled: true,
			wantHeaders: false,
		},
		{
			name: "full security config",
			annotations: map[string]string{
				AnnotationSecurityEnabled:        "true",
				AnnotationSecurityXFrameOptions:  "SAMEORIGIN",
				AnnotationSecurityXContentType:   "nosniff",
				AnnotationSecurityXXSSProtection: "1; mode=block",
			},
			wantEnabled:  true,
			wantHeaders:  true,
			wantXFrame:   "SAMEORIGIN",
			wantXContent: "nosniff",
			wantXXSS:     "1; mode=block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test"}

			converter.applyGRPCSecurityAnnotations(route, tt.annotations)

			if tt.wantNil {
				if route.Security != nil {
					t.Error("Security should be nil")
				}
				return
			}

			if route.Security == nil {
				t.Fatal("Security should not be nil")
			}
			if route.Security.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", route.Security.Enabled, tt.wantEnabled)
			}
			if tt.wantHeaders {
				if route.Security.Headers == nil {
					t.Fatal("Headers should not be nil")
				}
				if route.Security.Headers.XFrameOptions != tt.wantXFrame {
					t.Errorf("XFrameOptions = %q, want %q", route.Security.Headers.XFrameOptions, tt.wantXFrame)
				}
				if route.Security.Headers.XContentTypeOptions != tt.wantXContent {
					t.Errorf("XContentTypeOptions = %q, want %q", route.Security.Headers.XContentTypeOptions, tt.wantXContent)
				}
				if route.Security.Headers.XXSSProtection != tt.wantXXSS {
					t.Errorf("XXSSProtection = %q, want %q", route.Security.Headers.XXSSProtection, tt.wantXXSS)
				}
			} else if route.Security.Headers != nil {
				t.Error("Headers should be nil")
			}
		})
	}
}

// ============================================================================
// applyGRPCEncodingAnnotations Tests
// ============================================================================

func TestApplyGRPCEncodingAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantNil     bool
		wantReqEnc  string
		wantResEnc  string
	}{
		{
			name:        "no encoding annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "request encoding only",
			annotations: map[string]string{
				AnnotationEncodingRequestContentType: "application/grpc",
			},
			wantReqEnc: "application/grpc",
		},
		{
			name: "response encoding only",
			annotations: map[string]string{
				AnnotationEncodingResponseContentType: "application/grpc+proto",
			},
			wantResEnc: "application/grpc+proto",
		},
		{
			name: "both encodings",
			annotations: map[string]string{
				AnnotationEncodingRequestContentType:  "application/grpc",
				AnnotationEncodingResponseContentType: "application/grpc+json",
			},
			wantReqEnc: "application/grpc",
			wantResEnc: "application/grpc+json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test"}

			converter.applyGRPCEncodingAnnotations(route, tt.annotations)

			if tt.wantNil {
				if route.Encoding != nil {
					t.Error("Encoding should be nil")
				}
				return
			}

			if route.Encoding == nil {
				t.Fatal("Encoding should not be nil")
			}
			if route.Encoding.RequestEncoding != tt.wantReqEnc {
				t.Errorf("RequestEncoding = %q, want %q", route.Encoding.RequestEncoding, tt.wantReqEnc)
			}
			if route.Encoding.ResponseEncoding != tt.wantResEnc {
				t.Errorf("ResponseEncoding = %q, want %q", route.Encoding.ResponseEncoding, tt.wantResEnc)
			}
		})
	}
}

// ============================================================================
// applyGRPCCacheAnnotations Tests
// ============================================================================

func TestApplyGRPCCacheAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		wantNil     bool
		wantEnabled bool
		wantTTL     config.Duration
	}{
		{
			name:        "no cache annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "enabled only",
			annotations: map[string]string{
				AnnotationCacheEnabled: "true",
			},
			wantEnabled: true,
		},
		{
			name: "disabled",
			annotations: map[string]string{
				AnnotationCacheEnabled: "false",
			},
			wantEnabled: false,
		},
		{
			name: "with TTL",
			annotations: map[string]string{
				AnnotationCacheEnabled: "true",
				AnnotationCacheTTL:     "10m",
			},
			wantEnabled: true,
			wantTTL:     config.Duration(10 * time.Minute),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test"}

			converter.applyGRPCCacheAnnotations(route, tt.annotations)

			if tt.wantNil {
				if route.Cache != nil {
					t.Error("Cache should be nil")
				}
				return
			}

			if route.Cache == nil {
				t.Fatal("Cache should not be nil")
			}
			if route.Cache.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", route.Cache.Enabled, tt.wantEnabled)
			}
			if route.Cache.TTL != tt.wantTTL {
				t.Errorf("TTL = %v, want %v", route.Cache.TTL, tt.wantTTL)
			}
		})
	}
}

// ============================================================================
// applyGRPCTLSAnnotations Tests
// ============================================================================

func TestApplyGRPCTLSAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		routeTLS       *config.RouteTLSConfig
		annotations    map[string]string
		wantMinVersion string
		wantMaxVersion string
	}{
		{
			name:        "nil TLS config",
			routeTLS:    nil,
			annotations: map[string]string{AnnotationTLSMinVersion: "TLS12"},
		},
		{
			name:           "min version only",
			routeTLS:       &config.RouteTLSConfig{},
			annotations:    map[string]string{AnnotationTLSMinVersion: "TLS12"},
			wantMinVersion: "TLS12",
		},
		{
			name:           "max version only",
			routeTLS:       &config.RouteTLSConfig{},
			annotations:    map[string]string{AnnotationTLSMaxVersion: "TLS13"},
			wantMaxVersion: "TLS13",
		},
		{
			name:     "both versions",
			routeTLS: &config.RouteTLSConfig{},
			annotations: map[string]string{
				AnnotationTLSMinVersion: "TLS12",
				AnnotationTLSMaxVersion: "TLS13",
			},
			wantMinVersion: "TLS12",
			wantMaxVersion: "TLS13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			route := &config.GRPCRoute{Name: "test", TLS: tt.routeTLS}

			converter.applyGRPCTLSAnnotations(route, tt.annotations)

			if tt.routeTLS == nil {
				if route.TLS != nil {
					t.Error("TLS should remain nil")
				}
				return
			}

			if route.TLS.MinVersion != tt.wantMinVersion {
				t.Errorf("MinVersion = %q, want %q", route.TLS.MinVersion, tt.wantMinVersion)
			}
			if route.TLS.MaxVersion != tt.wantMaxVersion {
				t.Errorf("MaxVersion = %q, want %q", route.TLS.MaxVersion, tt.wantMaxVersion)
			}
		})
	}
}

// ============================================================================
// applyGRPCBackendAnnotations Tests
// ============================================================================

func TestApplyGRPCBackendAnnotations_LoadBalancer(t *testing.T) {
	converter := NewIngressConverter()
	backend := &config.GRPCBackend{Name: "test"}
	annotations := map[string]string{
		AnnotationLoadBalancerAlgorithm: "round-robin",
	}

	converter.applyGRPCBackendAnnotations(backend, annotations)

	if backend.LoadBalancer == nil {
		t.Fatal("LoadBalancer should not be nil")
	}
	if backend.LoadBalancer.Algorithm != "round-robin" {
		t.Errorf("Algorithm = %q, want %q", backend.LoadBalancer.Algorithm, "round-robin")
	}
}

func TestApplyGRPCBackendAnnotations_AllAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	backend := &config.GRPCBackend{Name: "test"}
	annotations := map[string]string{
		AnnotationLoadBalancerAlgorithm:   "least-connections",
		AnnotationGRPCHealthCheckEnabled:  "true",
		AnnotationGRPCHealthCheckService:  "grpc.health.v1.Health",
		AnnotationCircuitBreakerEnabled:   "true",
		AnnotationCircuitBreakerThreshold: "10",
		AnnotationGRPCMaxIdleConns:        "50",
		AnnotationGRPCMaxConnsPerHost:     "100",
		AnnotationGRPCIdleConnTimeout:     "5m",
	}

	converter.applyGRPCBackendAnnotations(backend, annotations)

	if backend.LoadBalancer == nil {
		t.Fatal("LoadBalancer should not be nil")
	}
	if backend.HealthCheck == nil {
		t.Fatal("HealthCheck should not be nil")
	}
	if backend.CircuitBreaker == nil {
		t.Fatal("CircuitBreaker should not be nil")
	}
	if backend.ConnectionPool == nil {
		t.Fatal("ConnectionPool should not be nil")
	}
}

// ============================================================================
// applyGRPCHealthCheckAnnotations Tests
// ============================================================================

func TestApplyGRPCHealthCheckAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name                   string
		annotations            map[string]string
		wantNil                bool
		wantEnabled            bool
		wantService            string
		wantInterval           config.Duration
		wantTimeout            config.Duration
		wantHealthyThreshold   int
		wantUnhealthyThreshold int
	}{
		{
			name:        "no health check annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "enabled only",
			annotations: map[string]string{
				AnnotationGRPCHealthCheckEnabled: "true",
			},
			wantEnabled: true,
		},
		{
			name: "disabled",
			annotations: map[string]string{
				AnnotationGRPCHealthCheckEnabled: "false",
			},
			wantEnabled: false,
		},
		{
			name: "full config",
			annotations: map[string]string{
				AnnotationGRPCHealthCheckEnabled:            "true",
				AnnotationGRPCHealthCheckService:            "grpc.health.v1.Health",
				AnnotationGRPCHealthCheckInterval:           "15s",
				AnnotationGRPCHealthCheckTimeout:            "5s",
				AnnotationGRPCHealthCheckHealthyThreshold:   "3",
				AnnotationGRPCHealthCheckUnhealthyThreshold: "2",
			},
			wantEnabled:            true,
			wantService:            "grpc.health.v1.Health",
			wantInterval:           config.Duration(15 * time.Second),
			wantTimeout:            config.Duration(5 * time.Second),
			wantHealthyThreshold:   3,
			wantUnhealthyThreshold: 2,
		},
		{
			name: "invalid thresholds",
			annotations: map[string]string{
				AnnotationGRPCHealthCheckEnabled:            "true",
				AnnotationGRPCHealthCheckHealthyThreshold:   "invalid",
				AnnotationGRPCHealthCheckUnhealthyThreshold: "invalid",
			},
			wantEnabled:            true,
			wantHealthyThreshold:   0,
			wantUnhealthyThreshold: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			backend := &config.GRPCBackend{Name: "test"}

			converter.applyGRPCHealthCheckAnnotations(backend, tt.annotations)

			if tt.wantNil {
				if backend.HealthCheck != nil {
					t.Error("HealthCheck should be nil")
				}
				return
			}

			if backend.HealthCheck == nil {
				t.Fatal("HealthCheck should not be nil")
			}
			if backend.HealthCheck.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", backend.HealthCheck.Enabled, tt.wantEnabled)
			}
			if backend.HealthCheck.Service != tt.wantService {
				t.Errorf("Service = %q, want %q", backend.HealthCheck.Service, tt.wantService)
			}
			if backend.HealthCheck.Interval != tt.wantInterval {
				t.Errorf("Interval = %v, want %v", backend.HealthCheck.Interval, tt.wantInterval)
			}
			if backend.HealthCheck.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", backend.HealthCheck.Timeout, tt.wantTimeout)
			}
			if backend.HealthCheck.HealthyThreshold != tt.wantHealthyThreshold {
				t.Errorf("HealthyThreshold = %d, want %d", backend.HealthCheck.HealthyThreshold, tt.wantHealthyThreshold)
			}
			if backend.HealthCheck.UnhealthyThreshold != tt.wantUnhealthyThreshold {
				t.Errorf("UnhealthyThreshold = %d, want %d", backend.HealthCheck.UnhealthyThreshold, tt.wantUnhealthyThreshold)
			}
		})
	}
}

// ============================================================================
// applyGRPCCircuitBreakerAnnotations Tests
// ============================================================================

func TestApplyGRPCCircuitBreakerAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		annotations   map[string]string
		wantNil       bool
		wantEnabled   bool
		wantThreshold int
		wantTimeout   config.Duration
		wantHalfOpen  int
	}{
		{
			name:        "no circuit breaker annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "enabled only",
			annotations: map[string]string{
				AnnotationCircuitBreakerEnabled: "true",
			},
			wantEnabled: true,
		},
		{
			name: "full config",
			annotations: map[string]string{
				AnnotationCircuitBreakerEnabled:   "true",
				AnnotationCircuitBreakerThreshold: "10",
				AnnotationCircuitBreakerTimeout:   "60s",
				AnnotationCircuitBreakerHalfOpen:  "5",
			},
			wantEnabled:   true,
			wantThreshold: 10,
			wantTimeout:   config.Duration(60 * time.Second),
			wantHalfOpen:  5,
		},
		{
			name: "invalid values",
			annotations: map[string]string{
				AnnotationCircuitBreakerEnabled:   "true",
				AnnotationCircuitBreakerThreshold: "invalid",
				AnnotationCircuitBreakerHalfOpen:  "invalid",
			},
			wantEnabled:   true,
			wantThreshold: 0,
			wantHalfOpen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			backend := &config.GRPCBackend{Name: "test"}

			converter.applyGRPCCircuitBreakerAnnotations(backend, tt.annotations)

			if tt.wantNil {
				if backend.CircuitBreaker != nil {
					t.Error("CircuitBreaker should be nil")
				}
				return
			}

			if backend.CircuitBreaker == nil {
				t.Fatal("CircuitBreaker should not be nil")
			}
			if backend.CircuitBreaker.Enabled != tt.wantEnabled {
				t.Errorf("Enabled = %v, want %v", backend.CircuitBreaker.Enabled, tt.wantEnabled)
			}
			if backend.CircuitBreaker.Threshold != tt.wantThreshold {
				t.Errorf("Threshold = %d, want %d", backend.CircuitBreaker.Threshold, tt.wantThreshold)
			}
			if backend.CircuitBreaker.Timeout != tt.wantTimeout {
				t.Errorf("Timeout = %v, want %v", backend.CircuitBreaker.Timeout, tt.wantTimeout)
			}
			if backend.CircuitBreaker.HalfOpenRequests != tt.wantHalfOpen {
				t.Errorf("HalfOpenRequests = %d, want %d", backend.CircuitBreaker.HalfOpenRequests, tt.wantHalfOpen)
			}
		})
	}
}

// ============================================================================
// applyGRPCConnectionPoolAnnotations Tests
// ============================================================================

func TestApplyGRPCConnectionPoolAnnotations_TableDriven(t *testing.T) {
	tests := []struct {
		name            string
		annotations     map[string]string
		wantNil         bool
		wantMaxIdle     int
		wantMaxConns    int
		wantIdleTimeout config.Duration
	}{
		{
			name:        "no connection pool annotations",
			annotations: map[string]string{},
			wantNil:     true,
		},
		{
			name: "max idle only",
			annotations: map[string]string{
				AnnotationGRPCMaxIdleConns: "50",
			},
			wantMaxIdle: 50,
		},
		{
			name: "max conns only",
			annotations: map[string]string{
				AnnotationGRPCMaxConnsPerHost: "100",
			},
			wantMaxConns: 100,
		},
		{
			name: "idle timeout only",
			annotations: map[string]string{
				AnnotationGRPCIdleConnTimeout: "5m",
			},
			wantIdleTimeout: config.Duration(5 * time.Minute),
		},
		{
			name: "full config",
			annotations: map[string]string{
				AnnotationGRPCMaxIdleConns:    "50",
				AnnotationGRPCMaxConnsPerHost: "100",
				AnnotationGRPCIdleConnTimeout: "10m",
			},
			wantMaxIdle:     50,
			wantMaxConns:    100,
			wantIdleTimeout: config.Duration(10 * time.Minute),
		},
		{
			name: "invalid values",
			annotations: map[string]string{
				AnnotationGRPCMaxIdleConns:    "invalid",
				AnnotationGRPCMaxConnsPerHost: "invalid",
			},
			wantMaxIdle:  0,
			wantMaxConns: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converter := NewIngressConverter()
			backend := &config.GRPCBackend{Name: "test"}

			converter.applyGRPCConnectionPoolAnnotations(backend, tt.annotations)

			if tt.wantNil {
				if backend.ConnectionPool != nil {
					t.Error("ConnectionPool should be nil")
				}
				return
			}

			if backend.ConnectionPool == nil {
				t.Fatal("ConnectionPool should not be nil")
			}
			if backend.ConnectionPool.MaxIdleConns != tt.wantMaxIdle {
				t.Errorf("MaxIdleConns = %d, want %d", backend.ConnectionPool.MaxIdleConns, tt.wantMaxIdle)
			}
			if backend.ConnectionPool.MaxConnsPerHost != tt.wantMaxConns {
				t.Errorf("MaxConnsPerHost = %d, want %d", backend.ConnectionPool.MaxConnsPerHost, tt.wantMaxConns)
			}
			if backend.ConnectionPool.IdleConnTimeout != tt.wantIdleTimeout {
				t.Errorf("IdleConnTimeout = %v, want %v", backend.ConnectionPool.IdleConnTimeout, tt.wantIdleTimeout)
			}
		})
	}
}

// ============================================================================
// gRPC Key Generation Tests
// ============================================================================

func TestIngressGRPCRouteKey(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-ingress",
			Namespace: "prod",
		},
	}

	key := ingressGRPCRouteKey(ingress, 0, 1)
	expected := "ingress-grpc-prod-grpc-ingress-r0-p1"
	if key != expected {
		t.Errorf("ingressGRPCRouteKey() = %q, want %q", key, expected)
	}
}

func TestIngressGRPCBackendKey_WithService(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-ingress",
			Namespace: "prod",
		},
	}
	backend := networkingv1.IngressBackend{
		Service: &networkingv1.IngressServiceBackend{
			Name: "grpc-svc",
			Port: networkingv1.ServiceBackendPort{Number: 50051},
		},
	}

	key := ingressGRPCBackendKey(ingress, backend)
	expected := "ingress-grpc-prod-grpc-ingress-grpc-svc-50051"
	if key != expected {
		t.Errorf("ingressGRPCBackendKey() = %q, want %q", key, expected)
	}
}

func TestIngressGRPCBackendKey_NoService(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-ingress",
			Namespace: "prod",
		},
	}
	backend := networkingv1.IngressBackend{}

	key := ingressGRPCBackendKey(ingress, backend)
	expected := "ingress-grpc-prod-grpc-ingress-unknown"
	if key != expected {
		t.Errorf("ingressGRPCBackendKey() = %q, want %q", key, expected)
	}
}

func TestIngressGRPCDefaultRouteKey(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-ingress",
			Namespace: "prod",
		},
	}

	key := ingressGRPCDefaultRouteKey(ingress)
	expected := "ingress-grpc-prod-grpc-ingress-default"
	if key != expected {
		t.Errorf("ingressGRPCDefaultRouteKey() = %q, want %q", key, expected)
	}
}

func TestIngressGRPCDefaultBackendKey(t *testing.T) {
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-ingress",
			Namespace: "prod",
		},
	}

	key := ingressGRPCDefaultBackendKey(ingress)
	expected := "ingress-grpc-prod-grpc-ingress-default-backend"
	if key != expected {
		t.Errorf("ingressGRPCDefaultBackendKey() = %q, want %q", key, expected)
	}
}

// ============================================================================
// ConvertIngress gRPC Integration Tests
// ============================================================================

func newTestGRPCIngress(name, namespace string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-service",
											Port: networkingv1.ServiceBackendPort{
												Number: 50051,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestConvertIngress_GRPCProtocol(t *testing.T) {
	converter := NewIngressConverter()
	ingress := newTestGRPCIngress("grpc-test", "default")

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	// Should produce gRPC routes and backends, not HTTP
	if len(result.Routes) != 0 {
		t.Errorf("ConvertIngress() HTTP routes = %d, want 0", len(result.Routes))
	}
	if len(result.Backends) != 0 {
		t.Errorf("ConvertIngress() HTTP backends = %d, want 0", len(result.Backends))
	}
	if len(result.GRPCRoutes) != 1 {
		t.Errorf("ConvertIngress() gRPC routes = %d, want 1", len(result.GRPCRoutes))
	}
	if len(result.GRPCBackends) != 1 {
		t.Errorf("ConvertIngress() gRPC backends = %d, want 1", len(result.GRPCBackends))
	}

	// Verify gRPC route key format
	expectedRouteKey := "ingress-grpc-default-grpc-test-r0-p0"
	if _, ok := result.GRPCRoutes[expectedRouteKey]; !ok {
		t.Errorf("ConvertIngress() missing gRPC route key %q", expectedRouteKey)
	}

	// Verify gRPC route JSON
	routeJSON := result.GRPCRoutes[expectedRouteKey]
	var route config.GRPCRoute
	if err := json.Unmarshal(routeJSON, &route); err != nil {
		t.Fatalf("Failed to unmarshal gRPC route JSON: %v", err)
	}
	if route.Name != expectedRouteKey {
		t.Errorf("Route name = %q, want %q", route.Name, expectedRouteKey)
	}
	if len(route.Match) != 1 {
		t.Fatalf("Route match count = %d, want 1", len(route.Match))
	}
	if route.Match[0].Authority == nil || route.Match[0].Authority.Exact != "grpc.example.com" {
		t.Error("Route should have authority match for grpc.example.com")
	}
}

func TestConvertIngress_GRPCWithDefaultBackend(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-default",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "default-grpc-svc",
					Port: networkingv1.ServiceBackendPort{Number: 50051},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	if len(result.Routes) != 0 {
		t.Errorf("ConvertIngress() HTTP routes = %d, want 0", len(result.Routes))
	}
	if len(result.GRPCRoutes) != 1 {
		t.Errorf("ConvertIngress() gRPC routes = %d, want 1", len(result.GRPCRoutes))
	}
	if len(result.GRPCBackends) != 1 {
		t.Errorf("ConvertIngress() gRPC backends = %d, want 1", len(result.GRPCBackends))
	}

	// Verify default route key
	expectedRouteKey := "ingress-grpc-default-grpc-default-default"
	if _, ok := result.GRPCRoutes[expectedRouteKey]; !ok {
		t.Errorf("ConvertIngress() missing default gRPC route key %q", expectedRouteKey)
	}

	// Verify default route has catch-all match
	routeJSON := result.GRPCRoutes[expectedRouteKey]
	var route config.GRPCRoute
	if err := json.Unmarshal(routeJSON, &route); err != nil {
		t.Fatalf("Failed to unmarshal gRPC route JSON: %v", err)
	}
	if len(route.Match) != 1 || route.Match[0].Service == nil {
		t.Error("Default gRPC route should have service match")
	}
}

func TestConvertIngress_GRPCWithTLS(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-tls",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol:      "grpc",
				AnnotationTLSMinVersion: "TLS12",
				AnnotationTLSMaxVersion: "TLS13",
			},
		},
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"secure.grpc.example.com"},
					SecretName: "grpc-tls-secret",
				},
			},
			Rules: []networkingv1.IngressRule{
				{
					Host: "secure.grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "secure-grpc-svc",
											Port: networkingv1.ServiceBackendPort{Number: 443},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	if len(result.GRPCRoutes) != 1 {
		t.Fatalf("ConvertIngress() gRPC routes = %d, want 1", len(result.GRPCRoutes))
	}

	// Verify TLS is set on the gRPC route
	for _, routeJSON := range result.GRPCRoutes {
		var route config.GRPCRoute
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal gRPC route JSON: %v", err)
		}
		if route.TLS == nil {
			t.Error("gRPC route should have TLS config for TLS host")
		} else {
			if len(route.TLS.SNIHosts) != 1 || route.TLS.SNIHosts[0] != "secure.grpc.example.com" {
				t.Errorf("Route TLS SNIHosts = %v, want [secure.grpc.example.com]", route.TLS.SNIHosts)
			}
			if route.TLS.MinVersion != "TLS12" {
				t.Errorf("Route TLS MinVersion = %q, want %q", route.TLS.MinVersion, "TLS12")
			}
			if route.TLS.MaxVersion != "TLS13" {
				t.Errorf("Route TLS MaxVersion = %q, want %q", route.TLS.MaxVersion, "TLS13")
			}
		}
	}
}

func TestConvertIngress_GRPCWithAllAnnotations(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-full",
			Namespace: "default",
			Annotations: map[string]string{
				// Protocol
				AnnotationProtocol: "grpc",
				// gRPC matching
				AnnotationGRPCService:          "api.v1.UserService",
				AnnotationGRPCServiceMatchType: "exact",
				AnnotationGRPCMethod:           "GetUser",
				AnnotationGRPCMethodMatchType:  "exact",
				// Timeout
				AnnotationTimeout: "30s",
				// Retry
				AnnotationRetryAttempts:           "3",
				AnnotationRetryPerTryTimeout:      "5s",
				AnnotationGRPCRetryOn:             "unavailable,resource-exhausted",
				AnnotationGRPCBackoffBaseInterval: "100ms",
				AnnotationGRPCBackoffMaxInterval:  "1s",
				// Rate limit
				AnnotationRateLimitEnabled:   "true",
				AnnotationRateLimitRPS:       "1000",
				AnnotationRateLimitBurst:     "100",
				AnnotationRateLimitPerClient: "true",
				// CORS
				AnnotationCORSAllowOrigins:     "https://example.com",
				AnnotationCORSAllowMethods:     "POST",
				AnnotationCORSAllowHeaders:     "Content-Type, Authorization",
				AnnotationCORSAllowCredentials: "true",
				// Security
				AnnotationSecurityEnabled:       "true",
				AnnotationSecurityXFrameOptions: "DENY",
				// Encoding
				AnnotationEncodingRequestContentType:  "application/grpc",
				AnnotationEncodingResponseContentType: "application/grpc",
				// Cache
				AnnotationCacheEnabled: "true",
				AnnotationCacheTTL:     "5m",
				// Backend - Load balancer
				AnnotationLoadBalancerAlgorithm: "round-robin",
				// Backend - Health check
				AnnotationGRPCHealthCheckEnabled:            "true",
				AnnotationGRPCHealthCheckService:            "grpc.health.v1.Health",
				AnnotationGRPCHealthCheckInterval:           "10s",
				AnnotationGRPCHealthCheckTimeout:            "5s",
				AnnotationGRPCHealthCheckHealthyThreshold:   "2",
				AnnotationGRPCHealthCheckUnhealthyThreshold: "3",
				// Backend - Circuit breaker
				AnnotationCircuitBreakerEnabled:   "true",
				AnnotationCircuitBreakerThreshold: "5",
				AnnotationCircuitBreakerTimeout:   "30s",
				AnnotationCircuitBreakerHalfOpen:  "3",
				// Backend - Connection pool
				AnnotationGRPCMaxIdleConns:    "50",
				AnnotationGRPCMaxConnsPerHost: "100",
				AnnotationGRPCIdleConnTimeout: "5m",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-service",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	if len(result.GRPCRoutes) != 1 {
		t.Fatalf("ConvertIngress() gRPC routes = %d, want 1", len(result.GRPCRoutes))
	}
	if len(result.GRPCBackends) != 1 {
		t.Fatalf("ConvertIngress() gRPC backends = %d, want 1", len(result.GRPCBackends))
	}

	// Verify gRPC route has all configurations
	for _, routeJSON := range result.GRPCRoutes {
		var route config.GRPCRoute
		if err := json.Unmarshal(routeJSON, &route); err != nil {
			t.Fatalf("Failed to unmarshal gRPC route JSON: %v", err)
		}

		// Verify match
		if len(route.Match) != 1 {
			t.Fatalf("Route match count = %d, want 1", len(route.Match))
		}
		match := route.Match[0]
		if match.Service == nil || match.Service.Exact != "api.v1.UserService" {
			t.Error("Route should have exact service match")
		}
		if match.Method == nil || match.Method.Exact != "GetUser" {
			t.Error("Route should have exact method match")
		}

		// Verify timeout
		if route.Timeout != config.Duration(30*time.Second) {
			t.Errorf("Timeout = %v, want 30s", route.Timeout)
		}

		// Verify retries
		if route.Retries == nil {
			t.Fatal("Retries should not be nil")
		}
		if route.Retries.Attempts != 3 {
			t.Errorf("Retry attempts = %d, want 3", route.Retries.Attempts)
		}
		if route.Retries.RetryOn != "unavailable,resource-exhausted" {
			t.Errorf("RetryOn = %q, want %q", route.Retries.RetryOn, "unavailable,resource-exhausted")
		}
		if route.Retries.BackoffBaseInterval != config.Duration(100*time.Millisecond) {
			t.Errorf("BackoffBaseInterval = %v, want 100ms", route.Retries.BackoffBaseInterval)
		}

		// Verify rate limit
		if route.RateLimit == nil {
			t.Fatal("RateLimit should not be nil")
		}
		if !route.RateLimit.Enabled {
			t.Error("RateLimit should be enabled")
		}
		if route.RateLimit.RequestsPerSecond != 1000 {
			t.Errorf("RPS = %d, want 1000", route.RateLimit.RequestsPerSecond)
		}

		// Verify CORS
		if route.CORS == nil {
			t.Fatal("CORS should not be nil")
		}
		if len(route.CORS.AllowOrigins) != 1 {
			t.Errorf("AllowOrigins count = %d, want 1", len(route.CORS.AllowOrigins))
		}

		// Verify security
		if route.Security == nil {
			t.Fatal("Security should not be nil")
		}
		if !route.Security.Enabled {
			t.Error("Security should be enabled")
		}

		// Verify encoding
		if route.Encoding == nil {
			t.Fatal("Encoding should not be nil")
		}
		if route.Encoding.RequestEncoding != "application/grpc" {
			t.Errorf("RequestEncoding = %q, want %q", route.Encoding.RequestEncoding, "application/grpc")
		}

		// Verify cache
		if route.Cache == nil {
			t.Fatal("Cache should not be nil")
		}
		if !route.Cache.Enabled {
			t.Error("Cache should be enabled")
		}
	}

	// Verify gRPC backend has all configurations
	for _, backendJSON := range result.GRPCBackends {
		var backend config.GRPCBackend
		if err := json.Unmarshal(backendJSON, &backend); err != nil {
			t.Fatalf("Failed to unmarshal gRPC backend JSON: %v", err)
		}

		// Verify load balancer
		if backend.LoadBalancer == nil {
			t.Fatal("LoadBalancer should not be nil")
		}
		if backend.LoadBalancer.Algorithm != "round-robin" {
			t.Errorf("LB algorithm = %q, want %q", backend.LoadBalancer.Algorithm, "round-robin")
		}

		// Verify health check
		if backend.HealthCheck == nil {
			t.Fatal("HealthCheck should not be nil")
		}
		if !backend.HealthCheck.Enabled {
			t.Error("HealthCheck should be enabled")
		}
		if backend.HealthCheck.Service != "grpc.health.v1.Health" {
			t.Errorf("HealthCheck service = %q, want %q", backend.HealthCheck.Service, "grpc.health.v1.Health")
		}

		// Verify circuit breaker
		if backend.CircuitBreaker == nil {
			t.Fatal("CircuitBreaker should not be nil")
		}
		if !backend.CircuitBreaker.Enabled {
			t.Error("CircuitBreaker should be enabled")
		}
		if backend.CircuitBreaker.Threshold != 5 {
			t.Errorf("CB threshold = %d, want 5", backend.CircuitBreaker.Threshold)
		}

		// Verify connection pool
		if backend.ConnectionPool == nil {
			t.Fatal("ConnectionPool should not be nil")
		}
		if backend.ConnectionPool.MaxIdleConns != 50 {
			t.Errorf("MaxIdleConns = %d, want 50", backend.ConnectionPool.MaxIdleConns)
		}
		if backend.ConnectionPool.MaxConnsPerHost != 100 {
			t.Errorf("MaxConnsPerHost = %d, want 100", backend.ConnectionPool.MaxConnsPerHost)
		}
		if backend.ConnectionPool.IdleConnTimeout != config.Duration(5*time.Minute) {
			t.Errorf("IdleConnTimeout = %v, want 5m", backend.ConnectionPool.IdleConnTimeout)
		}
	}
}

func TestConvertIngress_GRPCMultipleRules(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-multi",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "users.grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.UserService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "user-service",
											Port: networkingv1.ServiceBackendPort{Number: 50051},
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "orders.grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1.OrderService",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "order-service",
											Port: networkingv1.ServiceBackendPort{Number: 50052},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := converter.ConvertIngress(ingress)
	if err != nil {
		t.Fatalf("ConvertIngress() error = %v", err)
	}

	if len(result.GRPCRoutes) != 2 {
		t.Errorf("ConvertIngress() gRPC routes = %d, want 2", len(result.GRPCRoutes))
	}
	if len(result.GRPCBackends) != 2 {
		t.Errorf("ConvertIngress() gRPC backends = %d, want 2", len(result.GRPCBackends))
	}
}

func TestConvertIngress_GRPCNoServiceBackend(t *testing.T) {
	converter := NewIngressConverter()
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "grpc-no-service",
			Namespace: "default",
			Annotations: map[string]string{
				AnnotationProtocol: "grpc",
			},
		},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{
				{
					Host: "grpc.example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api.v1",
									PathType: ptrPathType(networkingv1.PathTypePrefix),
									Backend:  networkingv1.IngressBackend{},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := converter.ConvertIngress(ingress)
	if err == nil {
		t.Error("ConvertIngress() should return error for gRPC backend with no service")
	}
}

// ============================================================================
// gRPC Protocol Constants Tests
// ============================================================================

func TestGRPCProtocolConstants(t *testing.T) {
	if ProtocolHTTP == "" {
		t.Error("ProtocolHTTP should not be empty")
	}
	if ProtocolGRPC == "" {
		t.Error("ProtocolGRPC should not be empty")
	}
	if ProtocolH2C == "" {
		t.Error("ProtocolH2C should not be empty")
	}
	if MatchTypeExact == "" {
		t.Error("MatchTypeExact should not be empty")
	}
	if MatchTypePrefix == "" {
		t.Error("MatchTypePrefix should not be empty")
	}
	if MatchTypeRegex == "" {
		t.Error("MatchTypeRegex should not be empty")
	}
}

func TestGRPCAnnotationConstants(t *testing.T) {
	annotations := []string{
		AnnotationProtocol,
		AnnotationGRPCService,
		AnnotationGRPCServiceMatchType,
		AnnotationGRPCMethod,
		AnnotationGRPCMethodMatchType,
		AnnotationGRPCRetryOn,
		AnnotationGRPCBackoffBaseInterval,
		AnnotationGRPCBackoffMaxInterval,
		AnnotationGRPCHealthCheckEnabled,
		AnnotationGRPCHealthCheckService,
		AnnotationGRPCHealthCheckInterval,
		AnnotationGRPCHealthCheckTimeout,
		AnnotationGRPCHealthCheckHealthyThreshold,
		AnnotationGRPCHealthCheckUnhealthyThreshold,
		AnnotationGRPCMaxIdleConns,
		AnnotationGRPCMaxConnsPerHost,
		AnnotationGRPCIdleConnTimeout,
	}

	for _, ann := range annotations {
		if ann == "" {
			t.Errorf("Annotation constant should not be empty")
		}
		if !hasPrefix(ann, AnnotationPrefix) {
			t.Errorf("Annotation %q should have prefix %q", ann, AnnotationPrefix)
		}
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

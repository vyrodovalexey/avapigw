// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"strings"
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func ptr[T any](v T) *T { return &v }

func newIngressTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)
	return scheme
}

// ============================================================================
// matchesIngressClass Tests
// ============================================================================

func TestIngressValidator_MatchesIngressClass(t *testing.T) {
	tests := []struct {
		name     string
		ingress  *networkingv1.Ingress
		expected bool
	}{
		{
			name: "spec.ingressClassName matches avapigw",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
				},
			},
			expected: true,
		},
		{
			name: "spec.ingressClassName is nginx",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("nginx"),
				},
			},
			expected: false,
		},
		{
			name: "nil className with matching annotation",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubernetes.io/ingress.class": "avapigw",
					},
				},
			},
			expected: true,
		},
		{
			name: "nil className with non-matching annotation",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"kubernetes.io/ingress.class": "nginx",
					},
				},
			},
			expected: false,
		},
		{
			name:     "nil className no annotations",
			ingress:  &networkingv1.Ingress{},
			expected: false,
		},
		{
			name: "nil className annotations exist but no ingress.class",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"other-annotation": "value",
					},
				},
			},
			expected: false,
		},
	}

	validator := &IngressValidator{IngressClassName: "avapigw"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.matchesIngressClass(tt.ingress)
			if result != tt.expected {
				t.Errorf("matchesIngressClass() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// ============================================================================
// ValidateCreate Tests
// ============================================================================

func TestIngressValidator_ValidateCreate(t *testing.T) {
	tests := []struct {
		name           string
		ingress        *networkingv1.Ingress
		existingRoutes []*avapigwv1alpha1.APIRoute
		wantErr        bool
		wantWarnings   bool
		errContains    string
	}{
		{
			name: "valid ingress with avapigw class",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "my-svc",
													Port: networkingv1.ServiceBackendPort{Number: 8080},
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
			wantErr: false,
		},
		{
			name: "ingress with different class - skip",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("nginx"),
				},
			},
			wantErr: false,
		},
		{
			name: "ingress with no class - skip",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec:       networkingv1.IngressSpec{},
			},
			wantErr: false,
		},
		{
			name: "valid ingress with annotation class",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"kubernetes.io/ingress.class": "avapigw",
					},
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
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "my-svc",
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
			},
			wantErr: false,
		},
		{
			name: "ingress with invalid host",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "invalid host with spaces",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			wantErr:     true,
			errContains: "contains spaces",
		},
		{
			name: "ingress with empty path",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			wantErr:     true,
			errContains: "path is required",
		},
		{
			name: "ingress with path not starting with /",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "api",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			wantErr:     true,
			errContains: "must start with '/'",
		},
		{
			name: "ingress with empty backend service name",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "",
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
			},
			wantErr:     true,
			errContains: "service.name is required",
		},
		{
			name: "ingress with invalid port 0",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc",
													Port: networkingv1.ServiceBackendPort{},
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
			wantErr:     true,
			errContains: "port",
		},
		{
			name: "ingress with invalid port 70000",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc",
													Port: networkingv1.ServiceBackendPort{Number: 70000},
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
			wantErr:     true,
			errContains: "must be between 1 and 65535",
		},
		{
			name: "ingress with port name instead of number",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc",
													Port: networkingv1.ServiceBackendPort{Name: "http"},
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
			wantErr: false,
		},
		{
			name: "ingress with TLS empty secret name",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"example.com"},
							SecretName: "",
						},
					},
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			wantErr:     true,
			errContains: "secretName is required",
		},
		{
			name: "ingress with TLS empty host",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{""},
							SecretName: "my-secret",
						},
					},
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name: "ingress with duplicate host/path",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc1",
													Port: networkingv1.ServiceBackendPort{Number: 80},
												},
											},
										},
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc2",
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
			},
			wantErr:     true,
			errContains: "duplicate host/path",
		},
		{
			name: "ingress with no rules and no default backend - warning",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
				},
			},
			wantErr:      false,
			wantWarnings: true,
		},
		{
			name: "ingress with default backend only",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					DefaultBackend: &networkingv1.IngressBackend{
						Service: &networkingv1.IngressServiceBackend{
							Name: "default-svc",
							Port: networkingv1.ServiceBackendPort{Number: 80},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ingress with invalid default backend",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					DefaultBackend: &networkingv1.IngressBackend{
						Service: &networkingv1.IngressServiceBackend{
							Name: "",
							Port: networkingv1.ServiceBackendPort{Number: 80},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "service.name is required",
		},
		{
			name: "ingress with nil HTTP in rule",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ingress with empty HTTP paths",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{},
								},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "at least one path is required",
		},
		{
			name: "ingress with resource backend",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Resource: &corev1.TypedLocalObjectReference{
													APIGroup: ptr("example.com"),
													Kind:     "StorageBucket",
													Name:     "my-bucket",
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
			wantErr: false,
		},
		{
			name: "ingress with neither service nor resource",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend:  networkingv1.IngressBackend{},
										},
									},
								},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "either service or resource must be specified",
		},
		{
			name: "ingress with APIRoute conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api/v1",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			existingRoutes: []*avapigwv1alpha1.APIRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "default"},
					Spec: avapigwv1alpha1.APIRouteSpec{
						Match: []avapigwv1alpha1.RouteMatch{
							{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "conflicts with existing APIRoutes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			builder := fake.NewClientBuilder().WithScheme(scheme)

			for _, route := range tt.existingRoutes {
				builder = builder.WithObjects(route)
			}

			fakeClient := builder.Build()

			validator := &IngressValidator{
				Client:           fakeClient,
				DuplicateChecker: NewDuplicateChecker(fakeClient),
				IngressClassName: "avapigw",
			}

			warnings, err := validator.ValidateCreate(context.Background(), tt.ingress)

			if tt.wantErr {
				if err == nil {
					t.Error("ValidateCreate() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCreate() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateCreate() unexpected error: %v", err)
				}
			}

			if tt.wantWarnings && len(warnings) == 0 {
				t.Error("ValidateCreate() expected warnings, got none")
			}
			if !tt.wantWarnings && len(warnings) > 0 {
				t.Errorf("ValidateCreate() unexpected warnings: %v", warnings)
			}
		})
	}
}

// ============================================================================
// ValidateUpdate Tests
// ============================================================================

func TestIngressValidator_ValidateUpdate(t *testing.T) {
	tests := []struct {
		name    string
		newObj  *networkingv1.Ingress
		wantErr bool
	}{
		{
			name: "valid update",
			newObj: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
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
			},
			wantErr: false,
		},
		{
			name: "update with different class - skip",
			newObj: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("nginx"),
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			validator := &IngressValidator{
				Client:           fakeClient,
				DuplicateChecker: NewDuplicateChecker(fakeClient),
				IngressClassName: "avapigw",
			}

			_, err := validator.ValidateUpdate(context.Background(), nil, tt.newObj)
			if tt.wantErr && err == nil {
				t.Error("ValidateUpdate() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateUpdate() unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// ValidateDelete Tests
// ============================================================================

func TestIngressValidator_ValidateDelete(t *testing.T) {
	validator := &IngressValidator{IngressClassName: "avapigw"}

	warnings, err := validator.ValidateDelete(context.Background(), &networkingv1.Ingress{})
	if err != nil {
		t.Errorf("ValidateDelete() error = %v, want nil", err)
	}
	if warnings != nil {
		t.Errorf("ValidateDelete() warnings = %v, want nil", warnings)
	}
}

// ============================================================================
// validateIngressHost Tests
// ============================================================================

func TestValidateIngressHost(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		wantErr     bool
		errContains string
	}{
		{"empty host", "", false, ""},
		{"valid host", "example.com", false, ""},
		{"valid subdomain", "api.example.com", false, ""},
		{"wildcard host", "*.example.com", false, ""},
		{"wildcard only", "*.", true, "must have a domain"},
		{"host with spaces", "example .com", true, "contains spaces"},
		{"host starting with dot", ".example.com", true, "must not start or end with a dot"},
		{"host ending with dot", "example.com.", true, "must not start or end with a dot"},
		{"host with empty label", "example..com", true, "contains empty label"},
		{"host with long label", strings.Repeat("a", 64) + ".com", true, "label exceeds 63 characters"},
		{"valid long label", strings.Repeat("a", 63) + ".com", false, ""},
		{"single label", "localhost", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIngressHost(tt.host)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateIngressHost(%q) expected error, got nil", tt.host)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateIngressHost(%q) error = %q, want to contain %q", tt.host, err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateIngressHost(%q) unexpected error: %v", tt.host, err)
				}
			}
		})
	}
}

// ============================================================================
// pathsOverlap Tests
// ============================================================================

func TestPathsOverlap(t *testing.T) {
	tests := []struct {
		name     string
		pathA    string
		pathB    string
		expected bool
	}{
		{"prefix of other", "/api", "/api/v1", true},
		{"other is prefix", "/api/v1", "/api", true},
		{"exact match", "/api", "/api", true},
		{"no overlap", "/api", "/other", false},
		{"root overlaps all", "/", "/anything", true},
		{"different paths", "/users", "/orders", false},
		{"partial match not prefix", "/api-v1", "/api-v2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pathsOverlap(tt.pathA, tt.pathB)
			if result != tt.expected {
				t.Errorf("pathsOverlap(%q, %q) = %v, want %v", tt.pathA, tt.pathB, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// buildAPIRoutePaths Tests
// ============================================================================

func TestBuildAPIRoutePaths(t *testing.T) {
	tests := []struct {
		name     string
		routes   *avapigwv1alpha1.APIRouteList
		expected map[string]string
	}{
		{
			name:     "empty list",
			routes:   &avapigwv1alpha1.APIRouteList{},
			expected: map[string]string{},
		},
		{
			name: "routes with prefix URIs",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route1"},
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"}},
							},
						},
					},
				},
			},
			expected: map[string]string{"/api/v1": "route1"},
		},
		{
			name: "routes with exact URIs",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route2"},
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{URI: &avapigwv1alpha1.URIMatch{Exact: "/api/v1/users"}},
							},
						},
					},
				},
			},
			expected: map[string]string{"/api/v1/users": "route2"},
		},
		{
			name: "routes with nil URI",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route3"},
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{URI: nil},
							},
						},
					},
				},
			},
			expected: map[string]string{},
		},
		{
			name: "routes with both prefix and exact",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route4"},
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api", Exact: "/api/exact"}},
							},
						},
					},
				},
			},
			expected: map[string]string{"/api": "route4", "/api/exact": "route4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildAPIRoutePaths(tt.routes)
			if len(result) != len(tt.expected) {
				t.Errorf("buildAPIRoutePaths() returned %d paths, want %d", len(result), len(tt.expected))
				return
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("buildAPIRoutePaths()[%q] = %q, want %q", k, result[k], v)
				}
			}
		})
	}
}

// ============================================================================
// findIngressPathConflicts Tests
// ============================================================================

func TestFindIngressPathConflicts(t *testing.T) {
	tests := []struct {
		name          string
		rules         []networkingv1.IngressRule
		existingPaths map[string]string
		wantConflicts int
	}{
		{
			name: "no conflicts",
			rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/users"},
							},
						},
					},
				},
			},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 0,
		},
		{
			name: "exact match conflict",
			rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api/v1"},
							},
						},
					},
				},
			},
			existingPaths: map[string]string{"/api/v1": "route1"},
			wantConflicts: 1,
		},
		{
			name: "prefix overlap conflict",
			rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api/v1/users"},
							},
						},
					},
				},
			},
			existingPaths: map[string]string{"/api/v1": "route1"},
			wantConflicts: 1,
		},
		{
			name: "rule with nil HTTP",
			rules: []networkingv1.IngressRule{
				{Host: "example.com"},
			},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflicts := findIngressPathConflicts(tt.rules, tt.existingPaths)
			if len(conflicts) != tt.wantConflicts {
				t.Errorf("findIngressPathConflicts() returned %d conflicts, want %d: %v",
					len(conflicts), tt.wantConflicts, conflicts)
			}
		})
	}
}

// ============================================================================
// appendPathConflicts Tests
// ============================================================================

func TestAppendPathConflicts(t *testing.T) {
	tests := []struct {
		name          string
		ingressPath   string
		existingPaths map[string]string
		wantConflicts int
	}{
		{
			name:          "exact match",
			ingressPath:   "/api/v1",
			existingPaths: map[string]string{"/api/v1": "route1"},
			wantConflicts: 1,
		},
		{
			name:          "prefix overlap",
			ingressPath:   "/api/v1/users",
			existingPaths: map[string]string{"/api/v1": "route1"},
			wantConflicts: 1,
		},
		{
			name:          "no overlap",
			ingressPath:   "/users",
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 0,
		},
		{
			name:          "empty existing paths",
			ingressPath:   "/api",
			existingPaths: map[string]string{},
			wantConflicts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflicts := appendPathConflicts(nil, tt.ingressPath, tt.existingPaths)
			if len(conflicts) != tt.wantConflicts {
				t.Errorf("appendPathConflicts() returned %d conflicts, want %d: %v",
					len(conflicts), tt.wantConflicts, conflicts)
			}
		})
	}
}

// ============================================================================
// checkAPIRouteConflicts Tests
// ============================================================================

func TestIngressValidator_CheckAPIRouteConflicts(t *testing.T) {
	t.Run("no existing APIRoutes", func(t *testing.T) {
		scheme := newIngressTestScheme()
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

		validator := &IngressValidator{
			Client:           fakeClient,
			DuplicateChecker: NewDuplicateChecker(fakeClient),
			IngressClassName: "avapigw",
		}

		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{
					{
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{Path: "/api"},
								},
							},
						},
					},
				},
			},
		}

		err := validator.checkAPIRouteConflicts(context.Background(), ingress)
		if err != nil {
			t.Errorf("checkAPIRouteConflicts() unexpected error: %v", err)
		}
	})

	t.Run("conflicting APIRoute exists", func(t *testing.T) {
		scheme := newIngressTestScheme()
		existingRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "default"},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
				},
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRoute).Build()

		validator := &IngressValidator{
			Client:           fakeClient,
			DuplicateChecker: NewDuplicateChecker(fakeClient),
			IngressClassName: "avapigw",
		}

		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
			Spec: networkingv1.IngressSpec{
				Rules: []networkingv1.IngressRule{
					{
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{Path: "/api/v1"},
								},
							},
						},
					},
				},
			},
		}

		err := validator.checkAPIRouteConflicts(context.Background(), ingress)
		if err == nil {
			t.Error("checkAPIRouteConflicts() expected error for conflicting route")
		}
	})

	t.Run("nil client", func(t *testing.T) {
		validator := &IngressValidator{
			Client:           nil,
			IngressClassName: "avapigw",
		}

		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		}

		err := validator.checkAPIRouteConflicts(context.Background(), ingress)
		if err != nil {
			t.Errorf("checkAPIRouteConflicts() with nil client should return nil, got: %v", err)
		}
	})
}

// ============================================================================
// checkDuplicateHostPaths Tests
// ============================================================================

func TestIngressValidator_CheckDuplicateHostPaths(t *testing.T) {
	validator := &IngressValidator{IngressClassName: "avapigw"}

	tests := []struct {
		name    string
		rules   []networkingv1.IngressRule
		wantErr bool
	}{
		{
			name: "no duplicates",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api", PathType: ptr(networkingv1.PathTypePrefix)},
								{Path: "/users", PathType: ptr(networkingv1.PathTypePrefix)},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate host/path/pathType",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api", PathType: ptr(networkingv1.PathTypePrefix)},
								{Path: "/api", PathType: ptr(networkingv1.PathTypePrefix)},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "same host/path different pathType",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api", PathType: ptr(networkingv1.PathTypePrefix)},
								{Path: "/api", PathType: ptr(networkingv1.PathTypeExact)},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "rule with nil HTTP",
			rules: []networkingv1.IngressRule{
				{Host: "example.com"},
			},
			wantErr: false,
		},
		{
			name: "nil pathType defaults to Prefix",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api"},
								{Path: "/api"},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.checkDuplicateHostPaths(tt.rules)
			if tt.wantErr && err == nil {
				t.Error("checkDuplicateHostPaths() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("checkDuplicateHostPaths() unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// validateTLS Tests
// ============================================================================

func TestIngressValidator_ValidateTLS(t *testing.T) {
	validator := &IngressValidator{IngressClassName: "avapigw"}

	tests := []struct {
		name       string
		tlsConfigs []networkingv1.IngressTLS
		rules      []networkingv1.IngressRule
		wantErr    bool
	}{
		{
			name: "valid TLS",
			tlsConfigs: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"example.com"},
					SecretName: "my-secret",
				},
			},
			rules: []networkingv1.IngressRule{
				{Host: "example.com"},
			},
			wantErr: false,
		},
		{
			name: "empty secret name",
			tlsConfigs: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"example.com"},
					SecretName: "",
				},
			},
			rules:   nil,
			wantErr: true,
		},
		{
			name: "empty host in hosts list",
			tlsConfigs: []networkingv1.IngressTLS{
				{
					Hosts:      []string{""},
					SecretName: "my-secret",
				},
			},
			rules:   nil,
			wantErr: true,
		},
		{
			name: "invalid host in TLS",
			tlsConfigs: []networkingv1.IngressTLS{
				{
					Hosts:      []string{"invalid host"},
					SecretName: "my-secret",
				},
			},
			rules:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateTLS(tt.tlsConfigs, tt.rules)
			if tt.wantErr && err == nil {
				t.Error("validateTLS() expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateTLS() unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// validateIngressBackend Tests
// ============================================================================

func TestIngressValidator_ValidateIngressBackend(t *testing.T) {
	validator := &IngressValidator{IngressClassName: "avapigw"}

	tests := []struct {
		name        string
		backend     *networkingv1.IngressBackend
		wantErr     bool
		errContains string
	}{
		{
			name: "valid service backend",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "my-svc",
					Port: networkingv1.ServiceBackendPort{Number: 8080},
				},
			},
			wantErr: false,
		},
		{
			name:        "no service and no resource",
			backend:     &networkingv1.IngressBackend{},
			wantErr:     true,
			errContains: "either service or resource must be specified",
		},
		{
			name: "empty service name",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "",
					Port: networkingv1.ServiceBackendPort{Number: 80},
				},
			},
			wantErr:     true,
			errContains: "service.name is required",
		},
		{
			name: "no port number and no port name",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "svc",
					Port: networkingv1.ServiceBackendPort{},
				},
			},
			wantErr:     true,
			errContains: "port",
		},
		{
			name: "port number 65536",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "svc",
					Port: networkingv1.ServiceBackendPort{Number: 65536},
				},
			},
			wantErr:     true,
			errContains: "must be between 1 and 65535",
		},
		{
			name: "negative port number",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "svc",
					Port: networkingv1.ServiceBackendPort{Number: -1},
				},
			},
			wantErr:     true,
			errContains: "must be between 1 and 65535",
		},
		{
			name: "valid port name",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "svc",
					Port: networkingv1.ServiceBackendPort{Name: "http"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid port number",
			backend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "svc",
					Port: networkingv1.ServiceBackendPort{Number: 443},
				},
			},
			wantErr: false,
		},
		{
			name: "resource backend",
			backend: &networkingv1.IngressBackend{
				Resource: &corev1.TypedLocalObjectReference{
					APIGroup: ptr("example.com"),
					Kind:     "StorageBucket",
					Name:     "my-bucket",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateIngressBackend(tt.backend, "test.backend")
			if tt.wantErr {
				if err == nil {
					t.Error("validateIngressBackend() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateIngressBackend() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateIngressBackend() unexpected error: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// validateRules Tests
// ============================================================================

func TestIngressValidator_ValidateRules(t *testing.T) {
	validator := &IngressValidator{IngressClassName: "avapigw"}

	tests := []struct {
		name        string
		rules       []networkingv1.IngressRule
		wantErr     bool
		errContains string
	}{
		{
			name: "valid rules",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptr(networkingv1.PathTypePrefix),
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
			wantErr: false,
		},
		{
			name: "invalid host",
			rules: []networkingv1.IngressRule{
				{
					Host: "invalid host",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: ptr(networkingv1.PathTypePrefix),
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
			wantErr:     true,
			errContains: "contains spaces",
		},
		{
			name: "nil HTTP skipped",
			rules: []networkingv1.IngressRule{
				{Host: "example.com"},
			},
			wantErr: false,
		},
		{
			name: "empty HTTP paths",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "at least one path is required",
		},
		{
			name: "invalid path",
			rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "no-slash",
									PathType: ptr(networkingv1.PathTypePrefix),
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
			wantErr:     true,
			errContains: "must start with '/'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateRules(tt.rules)
			if tt.wantErr {
				if err == nil {
					t.Error("validateRules() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateRules() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateRules() unexpected error: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// validateIngressPath Tests
// ============================================================================

func TestIngressValidator_ValidateIngressPath(t *testing.T) {
	validator := &IngressValidator{IngressClassName: "avapigw"}

	tests := []struct {
		name        string
		path        *networkingv1.HTTPIngressPath
		wantErr     bool
		errContains string
	}{
		{
			name: "valid path with Prefix type",
			path: &networkingv1.HTTPIngressPath{
				Path:     "/api",
				PathType: ptr(networkingv1.PathTypePrefix),
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: "svc",
						Port: networkingv1.ServiceBackendPort{Number: 80},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid path with Exact type",
			path: &networkingv1.HTTPIngressPath{
				Path:     "/api/v1/users",
				PathType: ptr(networkingv1.PathTypeExact),
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: "svc",
						Port: networkingv1.ServiceBackendPort{Number: 80},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid path with ImplementationSpecific type",
			path: &networkingv1.HTTPIngressPath{
				Path:     "/api",
				PathType: ptr(networkingv1.PathTypeImplementationSpecific),
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: "svc",
						Port: networkingv1.ServiceBackendPort{Number: 80},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid path type",
			path: &networkingv1.HTTPIngressPath{
				Path:     "/api",
				PathType: ptr(networkingv1.PathType("Invalid")),
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: "svc",
						Port: networkingv1.ServiceBackendPort{Number: 80},
					},
				},
			},
			wantErr:     true,
			errContains: "pathType must be Prefix, Exact, or ImplementationSpecific",
		},
		{
			name: "nil path type is valid",
			path: &networkingv1.HTTPIngressPath{
				Path: "/api",
				Backend: networkingv1.IngressBackend{
					Service: &networkingv1.IngressServiceBackend{
						Name: "svc",
						Port: networkingv1.ServiceBackendPort{Number: 80},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.validateIngressPath(tt.path, "test.path")
			if tt.wantErr {
				if err == nil {
					t.Error("validateIngressPath() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("validateIngressPath() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("validateIngressPath() unexpected error: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// ValidateCreate with nil DuplicateChecker
// ============================================================================

func TestIngressValidator_ValidateCreate_NilDuplicateChecker(t *testing.T) {
	scheme := newIngressTestScheme()
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &IngressValidator{
		Client:           fakeClient,
		DuplicateChecker: nil,
		IngressClassName: "avapigw",
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api",
									PathType: ptr(networkingv1.PathTypePrefix),
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

	_, err := validator.ValidateCreate(context.Background(), ingress)
	if err != nil {
		t.Errorf("ValidateCreate() with nil DuplicateChecker should not error, got: %v", err)
	}
}

// ============================================================================
// ValidateUpdate with APIRoute conflict
// ============================================================================

func TestIngressValidator_ValidateUpdate_WithConflict(t *testing.T) {
	scheme := newIngressTestScheme()
	existingRoute := &avapigwv1alpha1.APIRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "existing", Namespace: "default"},
		Spec: avapigwv1alpha1.APIRouteSpec{
			Match: []avapigwv1alpha1.RouteMatch{
				{URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"}},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRoute).Build()

	validator := &IngressValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
		IngressClassName: "avapigw",
	}

	newObj := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr("avapigw"),
			Rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/api/v1",
									PathType: ptr(networkingv1.PathTypePrefix),
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

	_, err := validator.ValidateUpdate(context.Background(), nil, newObj)
	if err == nil {
		t.Error("ValidateUpdate() should return error for conflicting route")
	}
}

// ============================================================================
// gRPC Ingress Tests - isGRPCIngress
// ============================================================================

func TestIngressValidator_IsGRPCIngress_TableDriven(t *testing.T) {
	tests := []struct {
		name     string
		ingress  *networkingv1.Ingress
		expected bool
	}{
		{
			name: "nil annotations",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Namespace:   "default",
					Annotations: nil,
				},
			},
			expected: false,
		},
		{
			name: "empty annotations",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Namespace:   "default",
					Annotations: map[string]string{},
				},
			},
			expected: false,
		},
		{
			name: "protocol grpc lowercase",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "grpc",
					},
				},
			},
			expected: true,
		},
		{
			name: "protocol GRPC uppercase",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "GRPC",
					},
				},
			},
			expected: true,
		},
		{
			name: "protocol gRPC mixed case",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "gRPC",
					},
				},
			},
			expected: true,
		},
		{
			name: "protocol GrPc mixed case",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "GrPc",
					},
				},
			},
			expected: true,
		},
		{
			name: "protocol http",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "http",
					},
				},
			},
			expected: false,
		},
		{
			name: "protocol h2c",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "h2c",
					},
				},
			},
			expected: false,
		},
		{
			name: "protocol https",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "https",
					},
				},
			},
			expected: false,
		},
		{
			name: "no protocol annotation",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"other-annotation": "value",
					},
				},
			},
			expected: false,
		},
		{
			name: "empty protocol value",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "",
					},
				},
			},
			expected: false,
		},
		{
			name: "protocol with whitespace",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": " grpc ",
					},
				},
			},
			expected: false, // EqualFold doesn't trim whitespace
		},
	}

	validator := &IngressValidator{IngressClassName: "avapigw"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isGRPCIngress(tt.ingress)
			if result != tt.expected {
				t.Errorf("isGRPCIngress() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// ============================================================================
// gRPC Ingress Tests - checkGRPCRouteConflicts
// ============================================================================

func TestIngressValidator_CheckGRPCRouteConflicts(t *testing.T) {
	tests := []struct {
		name           string
		ingress        *networkingv1.Ingress
		existingRoutes []*avapigwv1alpha1.GRPCRoute
		wantErr        bool
		errContains    string
	}{
		{
			name: "no existing GRPCRoutes - should pass",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "MyMethod",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: nil,
			wantErr:        false,
		},
		{
			name: "conflicting GRPCRoute - same service and authority",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "MyMethod",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Method:    &avapigwv1alpha1.StringMatch{Exact: "MyMethod"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "conflicts with existing GRPCRoutes",
		},
		{
			name: "non-conflicting GRPCRoute - different service",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "otherservice.OtherService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "non-conflicting GRPCRoute - different authority",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "other.example.com"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "GRPCRoute in different namespace - no conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "other-namespace"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			builder := fake.NewClientBuilder().WithScheme(scheme)

			for _, route := range tt.existingRoutes {
				builder = builder.WithObjects(route)
			}

			fakeClient := builder.Build()

			validator := &IngressValidator{
				Client:           fakeClient,
				DuplicateChecker: NewDuplicateChecker(fakeClient),
				IngressClassName: "avapigw",
			}

			err := validator.checkGRPCRouteConflicts(context.Background(), tt.ingress)

			if tt.wantErr {
				if err == nil {
					t.Error("checkGRPCRouteConflicts() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("checkGRPCRouteConflicts() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("checkGRPCRouteConflicts() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestIngressValidator_CheckGRPCRouteConflicts_NilClient(t *testing.T) {
	validator := &IngressValidator{
		Client:           nil,
		IngressClassName: "avapigw",
	}

	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			Annotations: map[string]string{
				"avapigw.io/protocol": "grpc",
			},
		},
	}

	err := validator.checkGRPCRouteConflicts(context.Background(), ingress)
	if err != nil {
		t.Errorf("checkGRPCRouteConflicts() with nil client should return nil, got: %v", err)
	}
}

// ============================================================================
// gRPC Ingress Tests - buildGRPCRouteServices
// ============================================================================

func TestBuildGRPCRouteServices(t *testing.T) {
	tests := []struct {
		name     string
		routes   *avapigwv1alpha1.GRPCRouteList
		expected []grpcRouteService
	}{
		{
			name:     "empty GRPCRouteList",
			routes:   &avapigwv1alpha1.GRPCRouteList{},
			expected: nil,
		},
		{
			name: "GRPCRoute with exact service match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route1"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", routeName: "route1"},
			},
		},
		{
			name: "GRPCRoute with prefix service match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route2"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{Prefix: "myservice."},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.", routeName: "route2"},
			},
		},
		{
			name: "GRPCRoute with method match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route3"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
									Method:  &avapigwv1alpha1.StringMatch{Exact: "GetUser"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", method: "GetUser", routeName: "route3"},
			},
		},
		{
			name: "GRPCRoute with prefix method match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route4"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
									Method:  &avapigwv1alpha1.StringMatch{Prefix: "Get"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", method: "Get", routeName: "route4"},
			},
		},
		{
			name: "GRPCRoute with authority match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route5"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
									Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc.example.com", routeName: "route5"},
			},
		},
		{
			name: "GRPCRoute with prefix authority match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route6"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
									Authority: &avapigwv1alpha1.StringMatch{Prefix: "grpc."},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc.", routeName: "route6"},
			},
		},
		{
			name: "multiple GRPCRoutes",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route-a"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "service.A"},
									Authority: &avapigwv1alpha1.StringMatch{Exact: "a.example.com"},
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{Name: "route-b"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "service.B"},
									Method:    &avapigwv1alpha1.StringMatch{Exact: "MethodB"},
									Authority: &avapigwv1alpha1.StringMatch{Exact: "b.example.com"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "service.A", authority: "a.example.com", routeName: "route-a"},
				{service: "service.B", method: "MethodB", authority: "b.example.com", routeName: "route-b"},
			},
		},
		{
			name: "GRPCRoute with multiple matches",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "multi-match"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "service.First"},
									Authority: &avapigwv1alpha1.StringMatch{Exact: "first.example.com"},
								},
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "service.Second"},
									Authority: &avapigwv1alpha1.StringMatch{Exact: "second.example.com"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "service.First", authority: "first.example.com", routeName: "multi-match"},
				{service: "service.Second", authority: "second.example.com", routeName: "multi-match"},
			},
		},
		{
			name: "GRPCRoute with nil service",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "nil-service"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   nil,
									Authority: &avapigwv1alpha1.StringMatch{Exact: "example.com"},
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "", authority: "example.com", routeName: "nil-service"},
			},
		},
		{
			name: "GRPCRoute with nil method",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "nil-method"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
									Method:  nil,
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", method: "", routeName: "nil-method"},
			},
		},
		{
			name: "GRPCRoute with nil authority",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "nil-authority"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
									Authority: nil,
								},
							},
						},
					},
				},
			},
			expected: []grpcRouteService{
				{service: "myservice.MyService", authority: "", routeName: "nil-authority"},
			},
		},
		{
			name: "GRPCRoute with empty match list",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						ObjectMeta: metav1.ObjectMeta{Name: "empty-match"},
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{},
						},
					},
				},
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGRPCRouteServices(tt.routes)

			if len(result) != len(tt.expected) {
				t.Errorf("buildGRPCRouteServices() returned %d services, want %d", len(result), len(tt.expected))
				return
			}

			for i, expected := range tt.expected {
				if result[i].service != expected.service {
					t.Errorf("buildGRPCRouteServices()[%d].service = %q, want %q", i, result[i].service, expected.service)
				}
				if result[i].method != expected.method {
					t.Errorf("buildGRPCRouteServices()[%d].method = %q, want %q", i, result[i].method, expected.method)
				}
				if result[i].authority != expected.authority {
					t.Errorf("buildGRPCRouteServices()[%d].authority = %q, want %q", i, result[i].authority, expected.authority)
				}
				if result[i].routeName != expected.routeName {
					t.Errorf("buildGRPCRouteServices()[%d].routeName = %q, want %q", i, result[i].routeName, expected.routeName)
				}
			}
		})
	}
}

// ============================================================================
// gRPC Ingress Tests - findIngressGRPCConflicts
// ============================================================================

func TestFindIngressGRPCConflicts(t *testing.T) {
	tests := []struct {
		name             string
		ingress          *networkingv1.Ingress
		existingServices []grpcRouteService
		wantConflicts    int
	}{
		{
			name: "no conflicts - empty existing services",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{},
			wantConflicts:    0,
		},
		{
			name: "no conflicts - different authority",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "other.example.com", routeName: "route1"},
			},
			wantConflicts: 0,
		},
		{
			name: "no conflicts - different service",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "otherservice.OtherService", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 0,
		},
		{
			name: "authority/host conflict with service match",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "service prefix conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService.SubService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "method conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "GetUser",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", method: "GetUser", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "method prefix conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "GetUserDetails",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", method: "GetUser", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "nil annotations - no conflicts",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Namespace:   "default",
					Annotations: nil,
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 0,
		},
		{
			name: "empty host - no conflicts",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: ""},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 0,
		},
		{
			name: "both match all services - conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Namespace:   "default",
					Annotations: map[string]string{},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "multiple rules - one conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc1.example.com"},
						{Host: "grpc2.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc2.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "authority prefix conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", authority: "grpc", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "no method in ingress but method in existing - conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", method: "GetUser", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
		{
			name: "method in ingress but no method in existing - conflict",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "GetUser",
					},
				},
				Spec: networkingv1.IngressSpec{
					Rules: []networkingv1.IngressRule{
						{Host: "grpc.example.com"},
					},
				},
			},
			existingServices: []grpcRouteService{
				{service: "myservice.MyService", method: "", authority: "grpc.example.com", routeName: "route1"},
			},
			wantConflicts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflicts := findIngressGRPCConflicts(tt.ingress, tt.existingServices)
			if len(conflicts) != tt.wantConflicts {
				t.Errorf("findIngressGRPCConflicts() returned %d conflicts, want %d: %v",
					len(conflicts), tt.wantConflicts, conflicts)
			}
		})
	}
}

// ============================================================================
// gRPC Ingress Tests - ValidateCreate with gRPC Protocol
// ============================================================================

func TestIngressValidator_ValidateCreate_GRPCProtocol(t *testing.T) {
	tests := []struct {
		name           string
		ingress        *networkingv1.Ingress
		existingRoutes []*avapigwv1alpha1.GRPCRoute
		wantErr        bool
		errContains    string
	}{
		{
			name: "valid gRPC Ingress - no existing routes",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "MyMethod",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: nil,
			wantErr:        false,
		},
		{
			name: "gRPC Ingress with conflicting GRPCRoute",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
						"avapigw.io/grpc-method":  "MyMethod",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Method:    &avapigwv1alpha1.StringMatch{Exact: "MyMethod"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "conflicts with existing GRPCRoutes",
		},
		{
			name: "gRPC Ingress with non-conflicting GRPCRoute",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "otherservice.OtherService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "gRPC Ingress with uppercase GRPC protocol",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "GRPC",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "conflicts with existing GRPCRoutes",
		},
		{
			name: "HTTP Ingress should check APIRoute conflicts not GRPCRoute",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "http-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol": "http",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "api.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/api",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "api-svc",
													Port: networkingv1.ServiceBackendPort{Number: 8080},
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
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "api.example.com"},
							},
						},
					},
				},
			},
			wantErr: false, // HTTP Ingress should not conflict with GRPCRoute
		},
		{
			name: "gRPC Ingress with TLS",
			ingress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-tls-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					TLS: []networkingv1.IngressTLS{
						{
							Hosts:      []string{"grpc.example.com"},
							SecretName: "grpc-tls-secret",
						},
					},
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: nil,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			builder := fake.NewClientBuilder().WithScheme(scheme)

			for _, route := range tt.existingRoutes {
				builder = builder.WithObjects(route)
			}

			fakeClient := builder.Build()

			validator := &IngressValidator{
				Client:           fakeClient,
				DuplicateChecker: NewDuplicateChecker(fakeClient),
				IngressClassName: "avapigw",
			}

			_, err := validator.ValidateCreate(context.Background(), tt.ingress)

			if tt.wantErr {
				if err == nil {
					t.Error("ValidateCreate() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateCreate() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateCreate() unexpected error: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// gRPC Ingress Tests - ValidateUpdate with gRPC Protocol
// ============================================================================

func TestIngressValidator_ValidateUpdate_GRPCProtocol(t *testing.T) {
	tests := []struct {
		name           string
		newIngress     *networkingv1.Ingress
		existingRoutes []*avapigwv1alpha1.GRPCRoute
		wantErr        bool
		errContains    string
	}{
		{
			name: "valid gRPC Ingress update - no conflicts",
			newIngress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: nil,
			wantErr:        false,
		},
		{
			name: "gRPC Ingress update with conflict",
			newIngress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "grpc-svc",
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
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr:     true,
			errContains: "conflicts with existing GRPCRoutes",
		},
		{
			name: "update changing from HTTP to gRPC protocol",
			newIngress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("avapigw"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "api.example.com",
							IngressRuleValue: networkingv1.IngressRuleValue{
								HTTP: &networkingv1.HTTPIngressRuleValue{
									Paths: []networkingv1.HTTPIngressPath{
										{
											Path:     "/myservice.MyService",
											PathType: ptr(networkingv1.PathTypePrefix),
											Backend: networkingv1.IngressBackend{
												Service: &networkingv1.IngressServiceBackend{
													Name: "svc",
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
			},
			existingRoutes: nil,
			wantErr:        false,
		},
		{
			name: "update with different IngressClass - skip validation",
			newIngress: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-ingress",
					Namespace: "default",
					Annotations: map[string]string{
						"avapigw.io/protocol":     "grpc",
						"avapigw.io/grpc-service": "myservice.MyService",
					},
				},
				Spec: networkingv1.IngressSpec{
					IngressClassName: ptr("nginx"),
					Rules: []networkingv1.IngressRule{
						{
							Host: "grpc.example.com",
						},
					},
				},
			},
			existingRoutes: []*avapigwv1alpha1.GRPCRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
					Spec: avapigwv1alpha1.GRPCRouteSpec{
						Match: []avapigwv1alpha1.GRPCRouteMatch{
							{
								Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
								Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc.example.com"},
							},
						},
					},
				},
			},
			wantErr: false, // Different IngressClass, should skip validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newIngressTestScheme()
			builder := fake.NewClientBuilder().WithScheme(scheme)

			for _, route := range tt.existingRoutes {
				builder = builder.WithObjects(route)
			}

			fakeClient := builder.Build()

			validator := &IngressValidator{
				Client:           fakeClient,
				DuplicateChecker: NewDuplicateChecker(fakeClient),
				IngressClassName: "avapigw",
			}

			_, err := validator.ValidateUpdate(context.Background(), nil, tt.newIngress)

			if tt.wantErr {
				if err == nil {
					t.Error("ValidateUpdate() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateUpdate() error = %q, want to contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateUpdate() unexpected error: %v", err)
				}
			}
		})
	}
}

// ============================================================================
// gRPC Ingress Tests - Edge Cases
// ============================================================================

func TestIngressValidator_GRPCIngress_EdgeCases(t *testing.T) {
	t.Run("gRPC Ingress with nil DuplicateChecker", func(t *testing.T) {
		scheme := newIngressTestScheme()
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

		validator := &IngressValidator{
			Client:           fakeClient,
			DuplicateChecker: nil,
			IngressClassName: "avapigw",
		}

		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grpc-ingress",
				Namespace: "default",
				Annotations: map[string]string{
					"avapigw.io/protocol":     "grpc",
					"avapigw.io/grpc-service": "myservice.MyService",
				},
			},
			Spec: networkingv1.IngressSpec{
				IngressClassName: ptr("avapigw"),
				Rules: []networkingv1.IngressRule{
					{
						Host: "grpc.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/myservice.MyService",
										PathType: ptr(networkingv1.PathTypePrefix),
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "grpc-svc",
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

		_, err := validator.ValidateCreate(context.Background(), ingress)
		if err != nil {
			t.Errorf("ValidateCreate() with nil DuplicateChecker should not error, got: %v", err)
		}
	})

	t.Run("gRPC Ingress with multiple hosts", func(t *testing.T) {
		scheme := newIngressTestScheme()
		existingRoute := &avapigwv1alpha1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "existing-grpc", Namespace: "default"},
			Spec: avapigwv1alpha1.GRPCRouteSpec{
				Match: []avapigwv1alpha1.GRPCRouteMatch{
					{
						Service:   &avapigwv1alpha1.StringMatch{Exact: "myservice.MyService"},
						Authority: &avapigwv1alpha1.StringMatch{Exact: "grpc2.example.com"},
					},
				},
			},
		}
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existingRoute).Build()

		validator := &IngressValidator{
			Client:           fakeClient,
			DuplicateChecker: NewDuplicateChecker(fakeClient),
			IngressClassName: "avapigw",
		}

		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grpc-ingress",
				Namespace: "default",
				Annotations: map[string]string{
					"avapigw.io/protocol":     "grpc",
					"avapigw.io/grpc-service": "myservice.MyService",
				},
			},
			Spec: networkingv1.IngressSpec{
				IngressClassName: ptr("avapigw"),
				Rules: []networkingv1.IngressRule{
					{
						Host: "grpc1.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/myservice.MyService",
										PathType: ptr(networkingv1.PathTypePrefix),
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "grpc-svc",
												Port: networkingv1.ServiceBackendPort{Number: 50051},
											},
										},
									},
								},
							},
						},
					},
					{
						Host: "grpc2.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/myservice.MyService",
										PathType: ptr(networkingv1.PathTypePrefix),
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "grpc-svc",
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

		_, err := validator.ValidateCreate(context.Background(), ingress)
		if err == nil {
			t.Error("ValidateCreate() should return error for conflicting route on second host")
		}
	})

	t.Run("gRPC Ingress with wildcard host", func(t *testing.T) {
		scheme := newIngressTestScheme()
		fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

		validator := &IngressValidator{
			Client:           fakeClient,
			DuplicateChecker: NewDuplicateChecker(fakeClient),
			IngressClassName: "avapigw",
		}

		ingress := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "grpc-ingress",
				Namespace: "default",
				Annotations: map[string]string{
					"avapigw.io/protocol":     "grpc",
					"avapigw.io/grpc-service": "myservice.MyService",
				},
			},
			Spec: networkingv1.IngressSpec{
				IngressClassName: ptr("avapigw"),
				Rules: []networkingv1.IngressRule{
					{
						Host: "*.example.com",
						IngressRuleValue: networkingv1.IngressRuleValue{
							HTTP: &networkingv1.HTTPIngressRuleValue{
								Paths: []networkingv1.HTTPIngressPath{
									{
										Path:     "/myservice.MyService",
										PathType: ptr(networkingv1.PathTypePrefix),
										Backend: networkingv1.IngressBackend{
											Service: &networkingv1.IngressServiceBackend{
												Name: "grpc-svc",
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

		_, err := validator.ValidateCreate(context.Background(), ingress)
		if err != nil {
			t.Errorf("ValidateCreate() unexpected error for wildcard host: %v", err)
		}
	})
}

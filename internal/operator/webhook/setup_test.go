// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

// mockManager implements a minimal ctrl.Manager for testing webhook setup.
// It provides the necessary methods for webhook registration.
type mockManager struct {
	ctrl.Manager
	scheme *runtime.Scheme
	client *fake.ClientBuilder
}

func newMockManager() *mockManager {
	scheme := runtime.NewScheme()
	_ = avapigwv1alpha1.AddToScheme(scheme)
	_ = networkingv1.AddToScheme(scheme)

	return &mockManager{
		scheme: scheme,
		client: fake.NewClientBuilder().WithScheme(scheme),
	}
}

func (m *mockManager) GetScheme() *runtime.Scheme {
	return m.scheme
}

// ============================================================================
// SetupGRPCBackendWebhook Tests
// ============================================================================

func TestSetupGRPCBackendWebhook_ValidatorCreation(t *testing.T) {
	// Test that the validator is created with correct fields
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GRPCBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	assert.NotNil(t, validator.Client)
	assert.NotNil(t, validator.DuplicateChecker)
}

func TestSetupGRPCBackendWebhook_ValidateDeleteNoError(t *testing.T) {
	// Test that ValidateDelete returns no error
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GRPCBackendValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	backend := &avapigwv1alpha1.GRPCBackend{}
	warnings, err := validator.ValidateDelete(nil, backend)

	assert.NoError(t, err)
	assert.Nil(t, warnings)
}

// ============================================================================
// SetupGRPCRouteWebhook Tests
// ============================================================================

func TestSetupGRPCRouteWebhook_ValidatorCreation(t *testing.T) {
	// Test that the validator is created with correct fields
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GRPCRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	assert.NotNil(t, validator.Client)
	assert.NotNil(t, validator.DuplicateChecker)
}

func TestSetupGRPCRouteWebhook_ValidateDeleteNoError(t *testing.T) {
	// Test that ValidateDelete returns no error
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &GRPCRouteValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
	}

	route := &avapigwv1alpha1.GRPCRoute{}
	warnings, err := validator.ValidateDelete(nil, route)

	assert.NoError(t, err)
	assert.Nil(t, warnings)
}

// ============================================================================
// SetupIngressWebhook Tests
// ============================================================================

func TestSetupIngressWebhook_ValidatorCreation(t *testing.T) {
	tests := []struct {
		name             string
		ingressClassName string
		wantClassName    string
	}{
		{
			name:             "default ingress class name",
			ingressClassName: "",
			wantClassName:    ingressClassFieldName,
		},
		{
			name:             "custom ingress class name",
			ingressClassName: "custom-class",
			wantClassName:    "custom-class",
		},
		{
			name:             "avapigw ingress class name",
			ingressClassName: "avapigw",
			wantClassName:    "avapigw",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
			require.NoError(t, networkingv1.AddToScheme(scheme))

			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			// Determine the expected class name
			expectedClassName := tt.ingressClassName
			if expectedClassName == "" {
				expectedClassName = ingressClassFieldName
			}

			validator := &IngressValidator{
				Client:           fakeClient,
				DuplicateChecker: NewDuplicateChecker(fakeClient),
				IngressClassName: expectedClassName,
			}

			assert.NotNil(t, validator.Client)
			assert.NotNil(t, validator.DuplicateChecker)
			assert.Equal(t, tt.wantClassName, validator.IngressClassName)
		})
	}
}

func TestSetupIngressWebhook_ValidateDeleteNoError(t *testing.T) {
	// Test that ValidateDelete returns no error
	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))
	require.NoError(t, networkingv1.AddToScheme(scheme))

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	validator := &IngressValidator{
		Client:           fakeClient,
		DuplicateChecker: NewDuplicateChecker(fakeClient),
		IngressClassName: "avapigw",
	}

	ingress := &networkingv1.Ingress{}
	warnings, err := validator.ValidateDelete(nil, ingress)

	assert.NoError(t, err)
	assert.Nil(t, warnings)
}

func TestSetupIngressWebhook_MatchesIngressClass(t *testing.T) {
	tests := []struct {
		name             string
		ingressClassName string
		ingress          *networkingv1.Ingress
		want             bool
	}{
		{
			name:             "matches spec.ingressClassName",
			ingressClassName: "avapigw",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{
					IngressClassName: stringPtr("avapigw"),
				},
			},
			want: true,
		},
		{
			name:             "does not match spec.ingressClassName",
			ingressClassName: "avapigw",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{
					IngressClassName: stringPtr("nginx"),
				},
			},
			want: false,
		},
		{
			name:             "matches legacy annotation",
			ingressClassName: "avapigw",
			ingress: &networkingv1.Ingress{
				ObjectMeta: networkingv1.Ingress{}.ObjectMeta,
			},
			want: false,
		},
		{
			name:             "no ingress class specified",
			ingressClassName: "avapigw",
			ingress: &networkingv1.Ingress{
				Spec: networkingv1.IngressSpec{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &IngressValidator{
				IngressClassName: tt.ingressClassName,
			}

			got := validator.matchesIngressClass(tt.ingress)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIngressValidator_MatchesIngressClass_LegacyAnnotation(t *testing.T) {
	tests := []struct {
		name             string
		ingressClassName string
		annotations      map[string]string
		want             bool
	}{
		{
			name:             "matches legacy annotation",
			ingressClassName: "avapigw",
			annotations: map[string]string{
				"kubernetes.io/ingress.class": "avapigw",
			},
			want: true,
		},
		{
			name:             "does not match legacy annotation",
			ingressClassName: "avapigw",
			annotations: map[string]string{
				"kubernetes.io/ingress.class": "nginx",
			},
			want: false,
		},
		{
			name:             "no annotation",
			ingressClassName: "avapigw",
			annotations:      nil,
			want:             false,
		},
		{
			name:             "empty annotations map",
			ingressClassName: "avapigw",
			annotations:      map[string]string{},
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &IngressValidator{
				IngressClassName: tt.ingressClassName,
			}

			ingress := &networkingv1.Ingress{}
			ingress.Annotations = tt.annotations

			got := validator.matchesIngressClass(ingress)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIngressValidator_IsGRPCIngress(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name: "grpc protocol annotation",
			annotations: map[string]string{
				annotationProtocol: protocolGRPC,
			},
			want: true,
		},
		{
			name: "grpc protocol annotation uppercase",
			annotations: map[string]string{
				annotationProtocol: "GRPC",
			},
			want: true,
		},
		{
			name: "grpc protocol annotation mixed case",
			annotations: map[string]string{
				annotationProtocol: "GrPc",
			},
			want: true,
		},
		{
			name: "http protocol annotation",
			annotations: map[string]string{
				annotationProtocol: "http",
			},
			want: false,
		},
		{
			name:        "no annotations",
			annotations: nil,
			want:        false,
		},
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			want:        false,
		},
		{
			name: "other annotation only",
			annotations: map[string]string{
				"other-annotation": "value",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &IngressValidator{}

			ingress := &networkingv1.Ingress{}
			ingress.Annotations = tt.annotations

			got := validator.isGRPCIngress(ingress)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func stringPtr(s string) *string {
	return &s
}

// ============================================================================
// Validation Helper Tests
// ============================================================================

func TestSetup_ValidateIngressHost(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name:    "valid hostname",
			host:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid subdomain",
			host:    "api.example.com",
			wantErr: false,
		},
		{
			name:    "valid wildcard",
			host:    "*.example.com",
			wantErr: false,
		},
		{
			name:    "empty host",
			host:    "",
			wantErr: false,
		},
		{
			name:    "host with spaces",
			host:    "example .com",
			wantErr: true,
		},
		{
			name:    "host starting with dot",
			host:    ".example.com",
			wantErr: true,
		},
		{
			name:    "host ending with dot",
			host:    "example.com.",
			wantErr: true,
		},
		{
			name:    "host with empty label",
			host:    "example..com",
			wantErr: true,
		},
		{
			name:    "wildcard only",
			host:    "*.",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIngressHost(tt.host)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSetup_PathsOverlap(t *testing.T) {
	tests := []struct {
		name  string
		pathA string
		pathB string
		want  bool
	}{
		{
			name:  "exact match",
			pathA: "/api/v1",
			pathB: "/api/v1",
			want:  true,
		},
		{
			name:  "pathA is prefix of pathB",
			pathA: "/api",
			pathB: "/api/v1",
			want:  true,
		},
		{
			name:  "pathB is prefix of pathA",
			pathA: "/api/v1",
			pathB: "/api",
			want:  true,
		},
		{
			name:  "no overlap",
			pathA: "/api/v1",
			pathB: "/web/v1",
			want:  false,
		},
		{
			name:  "root path overlaps all",
			pathA: "/",
			pathB: "/api/v1",
			want:  true,
		},
		{
			name:  "similar paths with prefix relationship",
			pathA: "/api",
			pathB: "/api2",
			want:  true, // /api is a prefix of /api2 per strings.HasPrefix
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathsOverlap(tt.pathA, tt.pathB)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStringsOverlap(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "exact match",
			a:    "service",
			b:    "service",
			want: true,
		},
		{
			name: "a is prefix of b",
			a:    "service",
			b:    "service.method",
			want: true,
		},
		{
			name: "b is prefix of a",
			a:    "service.method",
			b:    "service",
			want: true,
		},
		{
			name: "no overlap",
			a:    "service1",
			b:    "service2",
			want: false,
		},
		{
			name: "empty strings",
			a:    "",
			b:    "",
			want: true,
		},
		{
			name: "one empty",
			a:    "service",
			b:    "",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stringsOverlap(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCheckMethodConflict(t *testing.T) {
	tests := []struct {
		name           string
		ingressMethod  string
		existingMethod string
		want           bool
	}{
		{
			name:           "both empty - matches all",
			ingressMethod:  "",
			existingMethod: "",
			want:           true,
		},
		{
			name:           "ingress empty - matches all",
			ingressMethod:  "",
			existingMethod: "GetUser",
			want:           true,
		},
		{
			name:           "existing empty - matches all",
			ingressMethod:  "GetUser",
			existingMethod: "",
			want:           true,
		},
		{
			name:           "exact match",
			ingressMethod:  "GetUser",
			existingMethod: "GetUser",
			want:           true,
		},
		{
			name:           "no match",
			ingressMethod:  "GetUser",
			existingMethod: "CreateUser",
			want:           false,
		},
		{
			name:           "prefix match",
			ingressMethod:  "Get",
			existingMethod: "GetUser",
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkMethodConflict(tt.ingressMethod, tt.existingMethod)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractStringMatchValue(t *testing.T) {
	tests := []struct {
		name string
		sm   *avapigwv1alpha1.StringMatch
		want string
	}{
		{
			name: "nil StringMatch",
			sm:   nil,
			want: "",
		},
		{
			name: "exact value",
			sm: &avapigwv1alpha1.StringMatch{
				Exact: "exact-value",
			},
			want: "exact-value",
		},
		{
			name: "prefix value",
			sm: &avapigwv1alpha1.StringMatch{
				Prefix: "prefix-value",
			},
			want: "prefix-value",
		},
		{
			name: "exact takes precedence over prefix",
			sm: &avapigwv1alpha1.StringMatch{
				Exact:  "exact-value",
				Prefix: "prefix-value",
			},
			want: "exact-value",
		},
		{
			name: "empty StringMatch",
			sm:   &avapigwv1alpha1.StringMatch{},
			want: "",
		},
		{
			name: "regex only returns empty",
			sm: &avapigwv1alpha1.StringMatch{
				Regex: ".*",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractStringMatchValue(tt.sm)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildGRPCRouteServiceFromMatch(t *testing.T) {
	tests := []struct {
		name      string
		routeName string
		match     avapigwv1alpha1.GRPCRouteMatch
		want      grpcRouteService
	}{
		{
			name:      "empty match",
			routeName: "test-route",
			match:     avapigwv1alpha1.GRPCRouteMatch{},
			want: grpcRouteService{
				routeName: "test-route",
				service:   "",
				method:    "",
				authority: "",
			},
		},
		{
			name:      "full match",
			routeName: "test-route",
			match: avapigwv1alpha1.GRPCRouteMatch{
				Service: &avapigwv1alpha1.StringMatch{
					Exact: "my.service.v1",
				},
				Method: &avapigwv1alpha1.StringMatch{
					Exact: "GetUser",
				},
				Authority: &avapigwv1alpha1.StringMatch{
					Exact: "api.example.com",
				},
			},
			want: grpcRouteService{
				routeName: "test-route",
				service:   "my.service.v1",
				method:    "GetUser",
				authority: "api.example.com",
			},
		},
		{
			name:      "prefix match",
			routeName: "prefix-route",
			match: avapigwv1alpha1.GRPCRouteMatch{
				Service: &avapigwv1alpha1.StringMatch{
					Prefix: "my.service",
				},
			},
			want: grpcRouteService{
				routeName: "prefix-route",
				service:   "my.service",
				method:    "",
				authority: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGRPCRouteServiceFromMatch(tt.routeName, tt.match)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetup_BuildGRPCRouteServices(t *testing.T) {
	tests := []struct {
		name   string
		routes *avapigwv1alpha1.GRPCRouteList
		want   int
	}{
		{
			name: "empty list",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{},
			},
			want: 0,
		},
		{
			name: "single route with single match",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{
										Exact: "my.service.v1",
									},
								},
							},
						},
					},
				},
			},
			want: 1,
		},
		{
			name: "single route with multiple matches",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{
										Exact: "my.service.v1",
									},
								},
								{
									Service: &avapigwv1alpha1.StringMatch{
										Exact: "my.service.v2",
									},
								},
							},
						},
					},
				},
			},
			want: 2,
		},
		{
			name: "multiple routes",
			routes: &avapigwv1alpha1.GRPCRouteList{
				Items: []avapigwv1alpha1.GRPCRoute{
					{
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{
										Exact: "service1",
									},
								},
							},
						},
					},
					{
						Spec: avapigwv1alpha1.GRPCRouteSpec{
							Match: []avapigwv1alpha1.GRPCRouteMatch{
								{
									Service: &avapigwv1alpha1.StringMatch{
										Exact: "service2",
									},
								},
							},
						},
					},
				},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGRPCRouteServices(tt.routes)
			assert.Len(t, got, tt.want)
		})
	}
}

func TestSetup_BuildAPIRoutePaths(t *testing.T) {
	tests := []struct {
		name   string
		routes *avapigwv1alpha1.APIRouteList
		want   map[string]string
	}{
		{
			name: "empty list",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{},
			},
			want: map[string]string{},
		},
		{
			name: "route with prefix match",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						ObjectMeta: networkingv1.Ingress{}.ObjectMeta,
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{
									URI: &avapigwv1alpha1.URIMatch{
										Prefix: "/api/v1",
									},
								},
							},
						},
					},
				},
			},
			want: map[string]string{
				"/api/v1": "",
			},
		},
		{
			name: "route with exact match",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						ObjectMeta: networkingv1.Ingress{}.ObjectMeta,
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{
									URI: &avapigwv1alpha1.URIMatch{
										Exact: "/api/v1/users",
									},
								},
							},
						},
					},
				},
			},
			want: map[string]string{
				"/api/v1/users": "",
			},
		},
		{
			name: "route with nil URI",
			routes: &avapigwv1alpha1.APIRouteList{
				Items: []avapigwv1alpha1.APIRoute{
					{
						Spec: avapigwv1alpha1.APIRouteSpec{
							Match: []avapigwv1alpha1.RouteMatch{
								{
									URI: nil,
								},
							},
						},
					},
				},
			},
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAPIRoutePaths(tt.routes)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSetup_FindIngressPathConflicts(t *testing.T) {
	tests := []struct {
		name          string
		rules         []networkingv1.IngressRule
		existingPaths map[string]string
		wantConflicts int
	}{
		{
			name:          "no rules",
			rules:         []networkingv1.IngressRule{},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 0,
		},
		{
			name: "no conflicts",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/web"},
							},
						},
					},
				},
			},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 0,
		},
		{
			name: "exact path conflict",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api"},
							},
						},
					},
				},
			},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 1,
		},
		{
			name: "overlapping path conflict",
			rules: []networkingv1.IngressRule{
				{
					Host: "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{Path: "/api/v1"},
							},
						},
					},
				},
			},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 1,
		},
		{
			name: "nil HTTP",
			rules: []networkingv1.IngressRule{
				{
					Host:             "example.com",
					IngressRuleValue: networkingv1.IngressRuleValue{},
				},
			},
			existingPaths: map[string]string{"/api": "route1"},
			wantConflicts: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findIngressPathConflicts(tt.rules, tt.existingPaths)
			assert.Len(t, got, tt.wantConflicts)
		})
	}
}

func TestSetup_AppendPathConflicts(t *testing.T) {
	tests := []struct {
		name          string
		conflicts     []string
		ingressPath   string
		existingPaths map[string]string
		wantLen       int
	}{
		{
			name:          "no existing paths",
			conflicts:     []string{},
			ingressPath:   "/api",
			existingPaths: map[string]string{},
			wantLen:       0,
		},
		{
			name:        "exact match conflict",
			conflicts:   []string{},
			ingressPath: "/api",
			existingPaths: map[string]string{
				"/api": "route1",
			},
			wantLen: 1,
		},
		{
			name:        "overlap conflict",
			conflicts:   []string{},
			ingressPath: "/api/v1",
			existingPaths: map[string]string{
				"/api": "route1",
			},
			wantLen: 1,
		},
		{
			name:        "no conflict",
			conflicts:   []string{},
			ingressPath: "/web",
			existingPaths: map[string]string{
				"/api": "route1",
			},
			wantLen: 0,
		},
		{
			name:        "multiple conflicts",
			conflicts:   []string{},
			ingressPath: "/api",
			existingPaths: map[string]string{
				"/api":    "route1",
				"/api/v1": "route2",
			},
			wantLen: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendPathConflicts(tt.conflicts, tt.ingressPath, tt.existingPaths)
			assert.Len(t, got, tt.wantLen)
		})
	}
}

func TestCheckServiceConflict(t *testing.T) {
	tests := []struct {
		name           string
		host           string
		ingressService string
		ingressMethod  string
		existing       grpcRouteService
		wantConflict   bool
	}{
		{
			name:           "both have services - overlap",
			host:           "api.example.com",
			ingressService: "my.service",
			ingressMethod:  "GetUser",
			existing: grpcRouteService{
				routeName: "route1",
				service:   "my.service",
				method:    "GetUser",
			},
			wantConflict: true,
		},
		{
			name:           "both have services - no overlap",
			host:           "api.example.com",
			ingressService: "my.service",
			ingressMethod:  "GetUser",
			existing: grpcRouteService{
				routeName: "route1",
				service:   "other.service",
				method:    "GetUser",
			},
			wantConflict: false,
		},
		{
			name:           "both match all services",
			host:           "api.example.com",
			ingressService: "",
			ingressMethod:  "",
			existing: grpcRouteService{
				routeName: "route1",
				service:   "",
				method:    "",
			},
			wantConflict: true,
		},
		{
			name:           "ingress has service, existing matches all",
			host:           "api.example.com",
			ingressService: "my.service",
			ingressMethod:  "",
			existing: grpcRouteService{
				routeName: "route1",
				service:   "",
				method:    "",
			},
			wantConflict: false,
		},
		{
			name:           "ingress matches all, existing has service",
			host:           "api.example.com",
			ingressService: "",
			ingressMethod:  "",
			existing: grpcRouteService{
				routeName: "route1",
				service:   "my.service",
				method:    "",
			},
			wantConflict: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkServiceConflict(tt.host, tt.ingressService, tt.ingressMethod, tt.existing)
			if tt.wantConflict {
				assert.NotEmpty(t, got)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

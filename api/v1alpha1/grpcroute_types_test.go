// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGRPCRoute_TypeMeta(t *testing.T) {
	route := &GRPCRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCRoute",
		},
	}

	if route.APIVersion != "avapigw.io/v1alpha1" {
		t.Errorf("APIVersion = %v, want avapigw.io/v1alpha1", route.APIVersion)
	}
	if route.Kind != "GRPCRoute" {
		t.Errorf("Kind = %v, want GRPCRoute", route.Kind)
	}
}

func TestGRPCRoute_ObjectMeta(t *testing.T) {
	route := &GRPCRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "test-namespace",
		},
	}

	if route.Name != "test-grpc-route" {
		t.Errorf("Name = %v, want test-grpc-route", route.Name)
	}
	if route.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", route.Namespace)
	}
}

func TestGRPCRouteSpec_Match(t *testing.T) {
	spec := GRPCRouteSpec{
		Match: []GRPCRouteMatch{
			{
				Service: &StringMatch{
					Exact: "api.v1.UserService",
				},
				Method: &StringMatch{
					Exact: "GetUser",
				},
			},
		},
	}

	if len(spec.Match) != 1 {
		t.Fatalf("Match length = %v, want 1", len(spec.Match))
	}
	if spec.Match[0].Service.Exact != "api.v1.UserService" {
		t.Errorf("Match[0].Service.Exact = %v, want api.v1.UserService", spec.Match[0].Service.Exact)
	}
	if spec.Match[0].Method.Exact != "GetUser" {
		t.Errorf("Match[0].Method.Exact = %v, want GetUser", spec.Match[0].Method.Exact)
	}
}

func TestGRPCRouteSpec_Route(t *testing.T) {
	spec := GRPCRouteSpec{
		Route: []RouteDestination{
			{
				Destination: Destination{
					Host: "grpc-backend",
					Port: 9000,
				},
				Weight: 100,
			},
		},
	}

	if len(spec.Route) != 1 {
		t.Fatalf("Route length = %v, want 1", len(spec.Route))
	}
	if spec.Route[0].Destination.Host != "grpc-backend" {
		t.Errorf("Route[0].Destination.Host = %v, want grpc-backend", spec.Route[0].Destination.Host)
	}
	if spec.Route[0].Destination.Port != 9000 {
		t.Errorf("Route[0].Destination.Port = %v, want 9000", spec.Route[0].Destination.Port)
	}
}

func TestGRPCRouteSpec_Timeout(t *testing.T) {
	spec := GRPCRouteSpec{
		Timeout: Duration("30s"),
	}

	if spec.Timeout != Duration("30s") {
		t.Errorf("Timeout = %v, want 30s", spec.Timeout)
	}
}

func TestGRPCRouteSpec_Retries(t *testing.T) {
	spec := GRPCRouteSpec{
		Retries: &GRPCRetryPolicy{
			Attempts:            3,
			PerTryTimeout:       Duration("10s"),
			RetryOn:             "unavailable,resource-exhausted",
			BackoffBaseInterval: Duration("100ms"),
			BackoffMaxInterval:  Duration("1s"),
		},
	}

	if spec.Retries == nil {
		t.Fatal("Retries should not be nil")
	}
	if spec.Retries.Attempts != 3 {
		t.Errorf("Retries.Attempts = %v, want 3", spec.Retries.Attempts)
	}
	if spec.Retries.RetryOn != "unavailable,resource-exhausted" {
		t.Errorf("Retries.RetryOn = %v, want unavailable,resource-exhausted", spec.Retries.RetryOn)
	}
	if spec.Retries.BackoffBaseInterval != Duration("100ms") {
		t.Errorf("Retries.BackoffBaseInterval = %v, want 100ms", spec.Retries.BackoffBaseInterval)
	}
}

func TestGRPCRouteSpec_Headers(t *testing.T) {
	spec := GRPCRouteSpec{
		Headers: &HeaderManipulation{
			Request: &HeaderOperation{
				Set: map[string]string{"x-gateway": "avapigw"},
			},
		},
	}

	if spec.Headers == nil {
		t.Fatal("Headers should not be nil")
	}
	if spec.Headers.Request.Set["x-gateway"] != "avapigw" {
		t.Errorf("Headers.Request.Set[x-gateway] = %v, want avapigw", spec.Headers.Request.Set["x-gateway"])
	}
}

func TestGRPCRouteSpec_Mirror(t *testing.T) {
	spec := GRPCRouteSpec{
		Mirror: &MirrorConfig{
			Destination: Destination{
				Host: "mirror-grpc-service",
				Port: 9000,
			},
			Percentage: 10,
		},
	}

	if spec.Mirror == nil {
		t.Fatal("Mirror should not be nil")
	}
	if spec.Mirror.Destination.Host != "mirror-grpc-service" {
		t.Errorf("Mirror.Destination.Host = %v, want mirror-grpc-service", spec.Mirror.Destination.Host)
	}
}

func TestGRPCRouteSpec_RateLimit(t *testing.T) {
	spec := GRPCRouteSpec{
		RateLimit: &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
		},
	}

	if spec.RateLimit == nil {
		t.Fatal("RateLimit should not be nil")
	}
	if !spec.RateLimit.Enabled {
		t.Error("RateLimit.Enabled should be true")
	}
}

func TestGRPCRouteSpec_Transform(t *testing.T) {
	spec := GRPCRouteSpec{
		Transform: &GRPCTransformConfig{
			FieldMask: &FieldMaskConfig{
				Paths: []string{"user.id", "user.name"},
			},
			Metadata: &MetadataManipulation{
				Static: map[string]string{
					"x-source": "gateway",
				},
				Dynamic: map[string]string{
					"x-request-id": "{{.RequestID}}",
				},
			},
		},
	}

	if spec.Transform == nil {
		t.Fatal("Transform should not be nil")
	}
	if spec.Transform.FieldMask == nil {
		t.Fatal("Transform.FieldMask should not be nil")
	}
	if len(spec.Transform.FieldMask.Paths) != 2 {
		t.Errorf("Transform.FieldMask.Paths length = %v, want 2", len(spec.Transform.FieldMask.Paths))
	}
	if spec.Transform.Metadata.Static["x-source"] != "gateway" {
		t.Errorf("Transform.Metadata.Static[x-source] = %v, want gateway", spec.Transform.Metadata.Static["x-source"])
	}
}

func TestGRPCRouteSpec_Cache(t *testing.T) {
	spec := GRPCRouteSpec{
		Cache: &CacheConfig{
			Enabled: true,
			TTL:     Duration("5m"),
		},
	}

	if spec.Cache == nil {
		t.Fatal("Cache should not be nil")
	}
	if !spec.Cache.Enabled {
		t.Error("Cache.Enabled should be true")
	}
}

func TestGRPCRouteSpec_Encoding(t *testing.T) {
	spec := GRPCRouteSpec{
		Encoding: &EncodingConfig{
			Request: &EncodingSettings{
				ContentType: "application/grpc",
			},
		},
	}

	if spec.Encoding == nil {
		t.Fatal("Encoding should not be nil")
	}
	if spec.Encoding.Request.ContentType != "application/grpc" {
		t.Errorf("Encoding.Request.ContentType = %v, want application/grpc", spec.Encoding.Request.ContentType)
	}
}

func TestGRPCRouteSpec_CORS(t *testing.T) {
	spec := GRPCRouteSpec{
		CORS: &CORSConfig{
			AllowOrigins: []string{"https://example.com"},
		},
	}

	if spec.CORS == nil {
		t.Fatal("CORS should not be nil")
	}
	if len(spec.CORS.AllowOrigins) != 1 {
		t.Errorf("CORS.AllowOrigins length = %v, want 1", len(spec.CORS.AllowOrigins))
	}
}

func TestGRPCRouteSpec_Security(t *testing.T) {
	spec := GRPCRouteSpec{
		Security: &SecurityConfig{
			Enabled: true,
		},
	}

	if spec.Security == nil {
		t.Fatal("Security should not be nil")
	}
	if !spec.Security.Enabled {
		t.Error("Security.Enabled should be true")
	}
}

func TestGRPCRouteSpec_TLS(t *testing.T) {
	spec := GRPCRouteSpec{
		TLS: &RouteTLSConfig{
			Vault: &VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "grpc-route",
				CommonName: "grpc.example.com",
			},
		},
	}

	if spec.TLS == nil {
		t.Fatal("TLS should not be nil")
	}
	if spec.TLS.Vault == nil {
		t.Fatal("TLS.Vault should not be nil")
	}
	if !spec.TLS.Vault.Enabled {
		t.Error("TLS.Vault.Enabled should be true")
	}
}

func TestGRPCRouteMatch_Service(t *testing.T) {
	tests := []struct {
		name  string
		match StringMatch
	}{
		{
			name: "exact service match",
			match: StringMatch{
				Exact: "api.v1.UserService",
			},
		},
		{
			name: "prefix service match",
			match: StringMatch{
				Prefix: "api.v1.",
			},
		},
		{
			name: "regex service match",
			match: StringMatch{
				Regex: "^api\\.v[0-9]+\\..*Service$",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grm := GRPCRouteMatch{
				Service: &tt.match,
			}
			if grm.Service == nil {
				t.Error("Service should not be nil")
			}
		})
	}
}

func TestGRPCRouteMatch_Method(t *testing.T) {
	tests := []struct {
		name  string
		match StringMatch
	}{
		{
			name: "exact method match",
			match: StringMatch{
				Exact: "GetUser",
			},
		},
		{
			name: "prefix method match",
			match: StringMatch{
				Prefix: "Get",
			},
		},
		{
			name: "regex method match",
			match: StringMatch{
				Regex: "^(Get|List|Create).*$",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grm := GRPCRouteMatch{
				Method: &tt.match,
			}
			if grm.Method == nil {
				t.Error("Method should not be nil")
			}
		})
	}
}

func TestGRPCRouteMatch_Authority(t *testing.T) {
	grm := GRPCRouteMatch{
		Authority: &StringMatch{
			Exact: "grpc.example.com",
		},
	}

	if grm.Authority == nil {
		t.Fatal("Authority should not be nil")
	}
	if grm.Authority.Exact != "grpc.example.com" {
		t.Errorf("Authority.Exact = %v, want grpc.example.com", grm.Authority.Exact)
	}
}

func TestGRPCRouteMatch_Metadata(t *testing.T) {
	present := true
	grm := GRPCRouteMatch{
		Metadata: []MetadataMatch{
			{
				Name:    "x-tenant-id",
				Present: &present,
			},
			{
				Name:  "x-api-version",
				Exact: "v1",
			},
			{
				Name:   "x-custom",
				Prefix: "prefix-",
			},
			{
				Name:  "x-pattern",
				Regex: "^[a-z]+$",
			},
		},
	}

	if len(grm.Metadata) != 4 {
		t.Fatalf("Metadata length = %v, want 4", len(grm.Metadata))
	}
	if grm.Metadata[0].Name != "x-tenant-id" {
		t.Errorf("Metadata[0].Name = %v, want x-tenant-id", grm.Metadata[0].Name)
	}
	if grm.Metadata[0].Present == nil || !*grm.Metadata[0].Present {
		t.Error("Metadata[0].Present should be true")
	}
	if grm.Metadata[1].Exact != "v1" {
		t.Errorf("Metadata[1].Exact = %v, want v1", grm.Metadata[1].Exact)
	}
}

func TestGRPCRouteMatch_WithoutHeaders(t *testing.T) {
	grm := GRPCRouteMatch{
		WithoutHeaders: []string{"x-internal", "x-debug"},
	}

	if len(grm.WithoutHeaders) != 2 {
		t.Fatalf("WithoutHeaders length = %v, want 2", len(grm.WithoutHeaders))
	}
	if grm.WithoutHeaders[0] != "x-internal" {
		t.Errorf("WithoutHeaders[0] = %v, want x-internal", grm.WithoutHeaders[0])
	}
}

func TestMetadataMatch_AllFields(t *testing.T) {
	present := true
	absent := false
	mm := MetadataMatch{
		Name:    "x-custom-header",
		Exact:   "exact-value",
		Prefix:  "prefix-",
		Regex:   "^[a-z]+$",
		Present: &present,
		Absent:  &absent,
	}

	if mm.Name != "x-custom-header" {
		t.Errorf("Name = %v, want x-custom-header", mm.Name)
	}
	if mm.Exact != "exact-value" {
		t.Errorf("Exact = %v, want exact-value", mm.Exact)
	}
	if mm.Prefix != "prefix-" {
		t.Errorf("Prefix = %v, want prefix-", mm.Prefix)
	}
	if mm.Regex != "^[a-z]+$" {
		t.Errorf("Regex = %v, want ^[a-z]+$", mm.Regex)
	}
	if mm.Present == nil || !*mm.Present {
		t.Error("Present should be true")
	}
	if mm.Absent == nil || *mm.Absent {
		t.Error("Absent should be false")
	}
}

func TestGRPCTransformConfig_FieldMaskOnly(t *testing.T) {
	tc := GRPCTransformConfig{
		FieldMask: &FieldMaskConfig{
			Paths: []string{"user.id", "user.name", "user.email"},
		},
	}

	if tc.FieldMask == nil {
		t.Fatal("FieldMask should not be nil")
	}
	if tc.Metadata != nil {
		t.Error("Metadata should be nil")
	}
	if len(tc.FieldMask.Paths) != 3 {
		t.Errorf("FieldMask.Paths length = %v, want 3", len(tc.FieldMask.Paths))
	}
}

func TestGRPCTransformConfig_MetadataOnly(t *testing.T) {
	tc := GRPCTransformConfig{
		Metadata: &MetadataManipulation{
			Static: map[string]string{
				"x-source":  "gateway",
				"x-version": "v1",
			},
			Dynamic: map[string]string{
				"x-request-id": "{{.RequestID}}",
				"x-timestamp":  "{{.Timestamp}}",
			},
		},
	}

	if tc.Metadata == nil {
		t.Fatal("Metadata should not be nil")
	}
	if tc.FieldMask != nil {
		t.Error("FieldMask should be nil")
	}
	if len(tc.Metadata.Static) != 2 {
		t.Errorf("Metadata.Static length = %v, want 2", len(tc.Metadata.Static))
	}
	if len(tc.Metadata.Dynamic) != 2 {
		t.Errorf("Metadata.Dynamic length = %v, want 2", len(tc.Metadata.Dynamic))
	}
}

func TestFieldMaskConfig_Paths(t *testing.T) {
	fmc := FieldMaskConfig{
		Paths: []string{
			"user.id",
			"user.name",
			"user.profile.avatar",
			"user.settings.notifications",
		},
	}

	if len(fmc.Paths) != 4 {
		t.Fatalf("Paths length = %v, want 4", len(fmc.Paths))
	}
	if fmc.Paths[0] != "user.id" {
		t.Errorf("Paths[0] = %v, want user.id", fmc.Paths[0])
	}
	if fmc.Paths[2] != "user.profile.avatar" {
		t.Errorf("Paths[2] = %v, want user.profile.avatar", fmc.Paths[2])
	}
}

func TestMetadataManipulation_AllFields(t *testing.T) {
	mm := MetadataManipulation{
		Static: map[string]string{
			"x-source":  "gateway",
			"x-version": "v1",
		},
		Dynamic: map[string]string{
			"x-request-id": "{{.RequestID}}",
		},
	}

	if len(mm.Static) != 2 {
		t.Errorf("Static length = %v, want 2", len(mm.Static))
	}
	if mm.Static["x-source"] != "gateway" {
		t.Errorf("Static[x-source] = %v, want gateway", mm.Static["x-source"])
	}
	if len(mm.Dynamic) != 1 {
		t.Errorf("Dynamic length = %v, want 1", len(mm.Dynamic))
	}
	if mm.Dynamic["x-request-id"] != "{{.RequestID}}" {
		t.Errorf("Dynamic[x-request-id] = %v, want {{.RequestID}}", mm.Dynamic["x-request-id"])
	}
}

func TestGRPCRouteStatus_Conditions(t *testing.T) {
	status := GRPCRouteStatus{
		Conditions: []Condition{
			{
				Type:               ConditionReady,
				Status:             metav1.ConditionTrue,
				Reason:             ReasonReconciled,
				Message:            "Route successfully applied",
				LastTransitionTime: metav1.Now(),
			},
		},
		ObservedGeneration: 1,
	}

	if len(status.Conditions) != 1 {
		t.Fatalf("Conditions length = %v, want 1", len(status.Conditions))
	}
	if status.Conditions[0].Type != ConditionReady {
		t.Errorf("Conditions[0].Type = %v, want Ready", status.Conditions[0].Type)
	}
	if status.ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %v, want 1", status.ObservedGeneration)
	}
}

func TestGRPCRouteStatus_AppliedGateways(t *testing.T) {
	status := GRPCRouteStatus{
		AppliedGateways: []AppliedGateway{
			{
				Name:        "gateway-1",
				Namespace:   "avapigw-system",
				LastApplied: metav1.Now(),
			},
		},
	}

	if len(status.AppliedGateways) != 1 {
		t.Fatalf("AppliedGateways length = %v, want 1", len(status.AppliedGateways))
	}
	if status.AppliedGateways[0].Name != "gateway-1" {
		t.Errorf("AppliedGateways[0].Name = %v, want gateway-1", status.AppliedGateways[0].Name)
	}
}

func TestGRPCRouteList_Items(t *testing.T) {
	list := &GRPCRouteList{
		Items: []GRPCRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-route-1",
					Namespace: "default",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-route-2",
					Namespace: "default",
				},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Fatalf("Items length = %v, want 2", len(list.Items))
	}
	if list.Items[0].Name != "grpc-route-1" {
		t.Errorf("Items[0].Name = %v, want grpc-route-1", list.Items[0].Name)
	}
}

func TestGRPCRoute_FullSpec(t *testing.T) {
	present := true
	route := &GRPCRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-grpc-route",
			Namespace: "default",
		},
		Spec: GRPCRouteSpec{
			Match: []GRPCRouteMatch{
				{
					Service: &StringMatch{
						Exact: "api.v1.UserService",
					},
					Method: &StringMatch{
						Exact: "GetUser",
					},
					Metadata: []MetadataMatch{
						{
							Name:    "x-tenant-id",
							Present: &present,
						},
					},
					Authority: &StringMatch{
						Exact: "grpc.example.com",
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{
						Host: "grpc-backend",
						Port: 9000,
					},
					Weight: 100,
				},
			},
			Timeout: Duration("30s"),
			Retries: &GRPCRetryPolicy{
				Attempts:            3,
				PerTryTimeout:       Duration("10s"),
				RetryOn:             "unavailable,resource-exhausted",
				BackoffBaseInterval: Duration("100ms"),
				BackoffMaxInterval:  Duration("1s"),
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
			Transform: &GRPCTransformConfig{
				FieldMask: &FieldMaskConfig{
					Paths: []string{"user.id", "user.name"},
				},
				Metadata: &MetadataManipulation{
					Static: map[string]string{
						"x-source": "gateway",
					},
				},
			},
			TLS: &RouteTLSConfig{
				Vault: &VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-route",
					CommonName: "grpc.example.com",
				},
			},
		},
		Status: GRPCRouteStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: metav1.Now(),
				},
			},
			ObservedGeneration: 1,
		},
	}

	// Verify all fields are set correctly
	if route.Name != "full-grpc-route" {
		t.Errorf("Name = %v, want full-grpc-route", route.Name)
	}
	if len(route.Spec.Match) != 1 {
		t.Errorf("Spec.Match length = %v, want 1", len(route.Spec.Match))
	}
	if route.Spec.Match[0].Service.Exact != "api.v1.UserService" {
		t.Errorf("Spec.Match[0].Service.Exact = %v, want api.v1.UserService", route.Spec.Match[0].Service.Exact)
	}
	if len(route.Spec.Route) != 1 {
		t.Errorf("Spec.Route length = %v, want 1", len(route.Spec.Route))
	}
	if route.Spec.Timeout != Duration("30s") {
		t.Errorf("Spec.Timeout = %v, want 30s", route.Spec.Timeout)
	}
	if route.Spec.Retries == nil {
		t.Error("Spec.Retries should not be nil")
	}
	if route.Spec.Transform == nil {
		t.Error("Spec.Transform should not be nil")
	}
	if route.Spec.TLS == nil {
		t.Error("Spec.TLS should not be nil")
	}
	if len(route.Status.Conditions) != 1 {
		t.Errorf("Status.Conditions length = %v, want 1", len(route.Status.Conditions))
	}
}

// Tests for GRPCRoute with Authentication configuration

func TestGRPCRouteSpec_Authentication(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCRouteSpec
	}{
		{
			name: "JWT authentication",
			spec: GRPCRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					JWT: &JWTAuthConfig{
						Enabled:   true,
						Issuer:    "https://issuer.example.com",
						JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
						Algorithm: "RS256",
					},
				},
			},
		},
		{
			name: "mTLS authentication",
			spec: GRPCRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					MTLS: &MTLSAuthConfig{
						Enabled:         true,
						CAFile:          "/certs/ca.crt",
						ExtractIdentity: "cn",
						AllowedCNs:      []string{"grpc-client1", "grpc-client2"},
					},
				},
			},
		},
		{
			name: "OIDC authentication",
			spec: GRPCRouteSpec{
				Authentication: &AuthenticationConfig{
					Enabled: true,
					OIDC: &OIDCAuthConfig{
						Enabled: true,
						Providers: []OIDCProviderConfig{
							{
								Name:      "keycloak",
								IssuerURL: "https://keycloak.example.com/realms/myrealm",
								ClientID:  "grpc-client",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Authentication == nil {
				t.Fatal("Authentication should not be nil")
			}
			if !tt.spec.Authentication.Enabled {
				t.Error("Authentication.Enabled should be true")
			}
		})
	}
}

func TestGRPCRouteSpec_Authentication_JWT_AllFields(t *testing.T) {
	spec := GRPCRouteSpec{
		Authentication: &AuthenticationConfig{
			Enabled: true,
			JWT: &JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://issuer.example.com",
				Audience:  []string{"grpc-api"},
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
				ClaimMapping: &ClaimMappingConfig{
					Roles:  "roles",
					Groups: "groups",
				},
			},
			SkipPaths: []string{"/grpc.health.v1.Health/Check"},
		},
	}

	jwt := spec.Authentication.JWT
	if jwt == nil {
		t.Fatal("JWT should not be nil")
	}
	if jwt.Issuer != "https://issuer.example.com" {
		t.Errorf("JWT.Issuer = %v, want https://issuer.example.com", jwt.Issuer)
	}
	if jwt.Algorithm != "RS256" {
		t.Errorf("JWT.Algorithm = %v, want RS256", jwt.Algorithm)
	}
	if len(spec.Authentication.SkipPaths) != 1 {
		t.Errorf("Authentication.SkipPaths length = %v, want 1", len(spec.Authentication.SkipPaths))
	}
}

// Tests for GRPCRoute with Authorization configuration

func TestGRPCRouteSpec_Authorization(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCRouteSpec
	}{
		{
			name: "RBAC authorization",
			spec: GRPCRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					RBAC: &RBACConfig{
						Enabled: true,
						Policies: []RBACPolicyConfig{
							{
								Name:      "admin-policy",
								Roles:     []string{"admin"},
								Resources: []string{"*"},
								Actions:   []string{"*"},
								Effect:    "allow",
							},
						},
					},
				},
			},
		},
		{
			name: "ABAC authorization",
			spec: GRPCRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					ABAC: &ABACConfig{
						Enabled: true,
						Policies: []ABACPolicyConfig{
							{
								Name:       "service-policy",
								Expression: "request.service in allowed_services",
								Effect:     "allow",
							},
						},
					},
				},
			},
		},
		{
			name: "External OPA authorization",
			spec: GRPCRouteSpec{
				Authorization: &AuthorizationConfig{
					Enabled:       true,
					DefaultPolicy: "deny",
					External: &ExternalAuthzConfig{
						Enabled: true,
						OPA: &OPAAuthzConfig{
							URL:    "http://opa:8181/v1/data/grpc/authz/allow",
							Policy: "grpc/authz/allow",
						},
						Timeout: Duration("5s"),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Authorization == nil {
				t.Fatal("Authorization should not be nil")
			}
			if !tt.spec.Authorization.Enabled {
				t.Error("Authorization.Enabled should be true")
			}
		})
	}
}

func TestGRPCRouteSpec_Authorization_RBAC_AllFields(t *testing.T) {
	spec := GRPCRouteSpec{
		Authorization: &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin"},
						Resources: []string{"api.v1.*"},
						Actions:   []string{"*"},
						Effect:    "allow",
						Priority:  100,
					},
					{
						Name:      "user-policy",
						Roles:     []string{"user"},
						Resources: []string{"api.v1.UserService/*"},
						Actions:   []string{"GetUser", "ListUsers"},
						Effect:    "allow",
						Priority:  50,
					},
				},
				RoleHierarchy: map[string][]string{
					"admin": {"user"},
				},
			},
			Cache: &AuthzCacheConfig{
				Enabled: true,
				TTL:     Duration("5m"),
				MaxSize: 1000,
				Type:    "memory",
			},
		},
	}

	rbac := spec.Authorization.RBAC
	if rbac == nil {
		t.Fatal("RBAC should not be nil")
	}
	if len(rbac.Policies) != 2 {
		t.Fatalf("RBAC.Policies length = %v, want 2", len(rbac.Policies))
	}
	if spec.Authorization.Cache == nil {
		t.Error("Authorization.Cache should not be nil")
	}
}

// Tests for GRPCRoute with MaxSessions configuration

func TestGRPCRouteSpec_MaxSessions(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCRouteSpec
	}{
		{
			name: "basic max sessions",
			spec: GRPCRouteSpec{
				MaxSessions: &MaxSessionsConfig{
					Enabled:       true,
					MaxConcurrent: 1000,
				},
			},
		},
		{
			name: "max sessions with queue",
			spec: GRPCRouteSpec{
				MaxSessions: &MaxSessionsConfig{
					Enabled:       true,
					MaxConcurrent: 500,
					QueueSize:     100,
					QueueTimeout:  Duration("30s"),
				},
			},
		},
		{
			name: "max sessions without queue",
			spec: GRPCRouteSpec{
				MaxSessions: &MaxSessionsConfig{
					Enabled:       true,
					MaxConcurrent: 100,
					QueueSize:     0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.MaxSessions == nil {
				t.Fatal("MaxSessions should not be nil")
			}
			if !tt.spec.MaxSessions.Enabled {
				t.Error("MaxSessions.Enabled should be true")
			}
			if tt.spec.MaxSessions.MaxConcurrent < 1 {
				t.Error("MaxSessions.MaxConcurrent should be at least 1")
			}
		})
	}
}

func TestGRPCRouteSpec_MaxSessions_AllFields(t *testing.T) {
	spec := GRPCRouteSpec{
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 500,
			QueueSize:     100,
			QueueTimeout:  Duration("30s"),
		},
	}

	ms := spec.MaxSessions
	if ms == nil {
		t.Fatal("MaxSessions should not be nil")
	}
	if !ms.Enabled {
		t.Error("MaxSessions.Enabled should be true")
	}
	if ms.MaxConcurrent != 500 {
		t.Errorf("MaxSessions.MaxConcurrent = %v, want 500", ms.MaxConcurrent)
	}
	if ms.QueueSize != 100 {
		t.Errorf("MaxSessions.QueueSize = %v, want 100", ms.QueueSize)
	}
	if ms.QueueTimeout != Duration("30s") {
		t.Errorf("MaxSessions.QueueTimeout = %v, want 30s", ms.QueueTimeout)
	}
}

// Tests for GRPCRoute with RequestLimits configuration

func TestGRPCRouteSpec_RequestLimits(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCRouteSpec
	}{
		{
			name: "body size limit only",
			spec: GRPCRouteSpec{
				RequestLimits: &RequestLimitsConfig{
					MaxBodySize: 10485760, // 10MB
				},
			},
		},
		{
			name: "header size limit only",
			spec: GRPCRouteSpec{
				RequestLimits: &RequestLimitsConfig{
					MaxHeaderSize: 1048576, // 1MB
				},
			},
		},
		{
			name: "both limits",
			spec: GRPCRouteSpec{
				RequestLimits: &RequestLimitsConfig{
					MaxBodySize:   10485760, // 10MB
					MaxHeaderSize: 1048576,  // 1MB
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.RequestLimits == nil {
				t.Fatal("RequestLimits should not be nil")
			}
		})
	}
}

func TestGRPCRouteSpec_RequestLimits_AllFields(t *testing.T) {
	spec := GRPCRouteSpec{
		RequestLimits: &RequestLimitsConfig{
			MaxBodySize:   52428800, // 50MB
			MaxHeaderSize: 2097152,  // 2MB
		},
	}

	rl := spec.RequestLimits
	if rl == nil {
		t.Fatal("RequestLimits should not be nil")
	}
	if rl.MaxBodySize != 52428800 {
		t.Errorf("RequestLimits.MaxBodySize = %v, want 52428800", rl.MaxBodySize)
	}
	if rl.MaxHeaderSize != 2097152 {
		t.Errorf("RequestLimits.MaxHeaderSize = %v, want 2097152", rl.MaxHeaderSize)
	}
}

// Tests for GRPCRoute with combined configurations

func TestGRPCRouteSpec_AuthenticationAndAuthorization(t *testing.T) {
	spec := GRPCRouteSpec{
		Match: []GRPCRouteMatch{
			{
				Service: &StringMatch{
					Prefix: "api.v1.",
				},
			},
		},
		Route: []RouteDestination{
			{
				Destination: Destination{
					Host: "grpc-backend",
					Port: 9000,
				},
			},
		},
		Authentication: &AuthenticationConfig{
			Enabled: true,
			JWT: &JWTAuthConfig{
				Enabled:   true,
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
				ClaimMapping: &ClaimMappingConfig{
					Roles: "roles",
				},
			},
		},
		Authorization: &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &RBACConfig{
				Enabled: true,
				Policies: []RBACPolicyConfig{
					{
						Name:   "admin-policy",
						Roles:  []string{"admin"},
						Effect: "allow",
					},
				},
			},
		},
	}

	if spec.Authentication == nil {
		t.Fatal("Authentication should not be nil")
	}
	if spec.Authorization == nil {
		t.Fatal("Authorization should not be nil")
	}
}

func TestGRPCRoute_FullSpecWithAllNewFields(t *testing.T) {
	route := &GRPCRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "secure-grpc-route",
			Namespace: "default",
		},
		Spec: GRPCRouteSpec{
			Match: []GRPCRouteMatch{
				{
					Service: &StringMatch{
						Exact: "api.v1.UserService",
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{
						Host: "grpc-backend",
						Port: 9000,
					},
				},
			},
			Timeout: Duration("30s"),
			Authentication: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled:   true,
					JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
					Algorithm: "RS256",
				},
			},
			Authorization: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &RBACConfig{
					Enabled: true,
					Policies: []RBACPolicyConfig{
						{
							Name:   "admin-policy",
							Roles:  []string{"admin"},
							Effect: "allow",
						},
					},
				},
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 500,
				QueueSize:     50,
				QueueTimeout:  Duration("10s"),
			},
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
			},
		},
		Status: GRPCRouteStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: metav1.Now(),
				},
			},
			ObservedGeneration: 1,
		},
	}

	if route.Name != "secure-grpc-route" {
		t.Errorf("Name = %v, want secure-grpc-route", route.Name)
	}
	if route.Spec.Authentication == nil {
		t.Error("Spec.Authentication should not be nil")
	}
	if route.Spec.Authorization == nil {
		t.Error("Spec.Authorization should not be nil")
	}
	if route.Spec.MaxSessions == nil {
		t.Error("Spec.MaxSessions should not be nil")
	}
	if route.Spec.RequestLimits == nil {
		t.Error("Spec.RequestLimits should not be nil")
	}
}

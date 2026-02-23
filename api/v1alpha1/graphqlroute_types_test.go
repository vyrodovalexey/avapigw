package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGraphQLRoute_TypeMeta(t *testing.T) {
	route := &GraphQLRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GraphQLRoute",
		},
	}

	if route.APIVersion != "avapigw.io/v1alpha1" {
		t.Errorf("APIVersion = %v, want avapigw.io/v1alpha1", route.APIVersion)
	}
	if route.Kind != "GraphQLRoute" {
		t.Errorf("Kind = %v, want GraphQLRoute", route.Kind)
	}
}

func TestGraphQLRoute_ObjectMeta(t *testing.T) {
	route := &GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
			Namespace: "test-namespace",
		},
	}

	if route.Name != "test-graphql-route" {
		t.Errorf("Name = %v, want test-graphql-route", route.Name)
	}
	if route.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", route.Namespace)
	}
}

func TestGraphQLRouteSpec_Match(t *testing.T) {
	spec := GraphQLRouteSpec{
		Match: []GraphQLRouteMatch{
			{
				Path: &StringMatch{
					Exact: "/graphql",
				},
				OperationType: "query",
				OperationName: &StringMatch{
					Exact: "GetUser",
				},
			},
		},
	}

	if len(spec.Match) != 1 {
		t.Fatalf("Match length = %v, want 1", len(spec.Match))
	}
	if spec.Match[0].Path.Exact != "/graphql" {
		t.Errorf("Match[0].Path.Exact = %v, want /graphql", spec.Match[0].Path.Exact)
	}
	if spec.Match[0].OperationType != "query" {
		t.Errorf("Match[0].OperationType = %v, want query", spec.Match[0].OperationType)
	}
	if spec.Match[0].OperationName.Exact != "GetUser" {
		t.Errorf("Match[0].OperationName.Exact = %v, want GetUser", spec.Match[0].OperationName.Exact)
	}
}

func TestGraphQLRouteSpec_Route(t *testing.T) {
	spec := GraphQLRouteSpec{
		Route: []RouteDestination{
			{
				Destination: Destination{
					Host: "graphql-backend",
					Port: 4000,
				},
				Weight: 100,
			},
		},
	}

	if len(spec.Route) != 1 {
		t.Fatalf("Route length = %v, want 1", len(spec.Route))
	}
	if spec.Route[0].Destination.Host != "graphql-backend" {
		t.Errorf("Route[0].Destination.Host = %v, want graphql-backend", spec.Route[0].Destination.Host)
	}
	if spec.Route[0].Destination.Port != 4000 {
		t.Errorf("Route[0].Destination.Port = %v, want 4000", spec.Route[0].Destination.Port)
	}
}

func TestGraphQLRouteSpec_GraphQLSpecificFields(t *testing.T) {
	introspectionEnabled := false
	spec := GraphQLRouteSpec{
		DepthLimit:           10,
		ComplexityLimit:      100,
		IntrospectionEnabled: &introspectionEnabled,
		AllowedOperations:    []string{"query", "mutation"},
	}

	if spec.DepthLimit != 10 {
		t.Errorf("DepthLimit = %v, want 10", spec.DepthLimit)
	}
	if spec.ComplexityLimit != 100 {
		t.Errorf("ComplexityLimit = %v, want 100", spec.ComplexityLimit)
	}
	if spec.IntrospectionEnabled == nil || *spec.IntrospectionEnabled {
		t.Error("IntrospectionEnabled should be false")
	}
	if len(spec.AllowedOperations) != 2 {
		t.Errorf("AllowedOperations length = %v, want 2", len(spec.AllowedOperations))
	}
}

func TestGraphQLRouteSpec_Timeout(t *testing.T) {
	spec := GraphQLRouteSpec{
		Timeout: Duration("30s"),
	}

	if spec.Timeout != Duration("30s") {
		t.Errorf("Timeout = %v, want 30s", spec.Timeout)
	}
}

func TestGraphQLRouteSpec_Headers(t *testing.T) {
	spec := GraphQLRouteSpec{
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

func TestGraphQLRouteSpec_RateLimit(t *testing.T) {
	spec := GraphQLRouteSpec{
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

func TestGraphQLRouteSpec_Cache(t *testing.T) {
	spec := GraphQLRouteSpec{
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

func TestGraphQLRouteSpec_CORS(t *testing.T) {
	spec := GraphQLRouteSpec{
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

func TestGraphQLRouteSpec_Security(t *testing.T) {
	spec := GraphQLRouteSpec{
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

func TestGraphQLRouteSpec_TLS(t *testing.T) {
	spec := GraphQLRouteSpec{
		TLS: &RouteTLSConfig{
			Vault: &VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "graphql-route",
				CommonName: "graphql.example.com",
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

func TestGraphQLRouteSpec_Authentication(t *testing.T) {
	spec := GraphQLRouteSpec{
		Authentication: &AuthenticationConfig{
			Enabled: true,
			JWT: &JWTAuthConfig{
				Enabled:   true,
				Issuer:    "https://issuer.example.com",
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
			},
		},
	}

	if spec.Authentication == nil {
		t.Fatal("Authentication should not be nil")
	}
	if !spec.Authentication.Enabled {
		t.Error("Authentication.Enabled should be true")
	}
	if spec.Authentication.JWT == nil {
		t.Fatal("Authentication.JWT should not be nil")
	}
}

func TestGraphQLRouteSpec_Authorization(t *testing.T) {
	spec := GraphQLRouteSpec{
		Authorization: &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
		},
	}

	if spec.Authorization == nil {
		t.Fatal("Authorization should not be nil")
	}
	if !spec.Authorization.Enabled {
		t.Error("Authorization.Enabled should be true")
	}
}

func TestGraphQLRouteSpec_MaxSessions(t *testing.T) {
	spec := GraphQLRouteSpec{
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 500,
		},
	}

	if spec.MaxSessions == nil {
		t.Fatal("MaxSessions should not be nil")
	}
	if !spec.MaxSessions.Enabled {
		t.Error("MaxSessions.Enabled should be true")
	}
}

func TestGraphQLRouteSpec_RequestLimits(t *testing.T) {
	spec := GraphQLRouteSpec{
		RequestLimits: &RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		},
	}

	if spec.RequestLimits == nil {
		t.Fatal("RequestLimits should not be nil")
	}
	if spec.RequestLimits.MaxBodySize != 10485760 {
		t.Errorf("RequestLimits.MaxBodySize = %v, want 10485760", spec.RequestLimits.MaxBodySize)
	}
}

func TestGraphQLRouteMatch_Headers(t *testing.T) {
	match := GraphQLRouteMatch{
		Headers: []GraphQLHeaderMatch{
			{Name: "Authorization", Prefix: "Bearer "},
			{Name: "X-Tenant", Exact: "acme"},
			{Name: "X-Version", Regex: "^v[0-9]+$"},
		},
	}

	if len(match.Headers) != 3 {
		t.Fatalf("Headers length = %v, want 3", len(match.Headers))
	}
	if match.Headers[0].Name != "Authorization" {
		t.Errorf("Headers[0].Name = %v, want Authorization", match.Headers[0].Name)
	}
	if match.Headers[0].Prefix != "Bearer " {
		t.Errorf("Headers[0].Prefix = %v, want 'Bearer '", match.Headers[0].Prefix)
	}
	if match.Headers[1].Exact != "acme" {
		t.Errorf("Headers[1].Exact = %v, want acme", match.Headers[1].Exact)
	}
	if match.Headers[2].Regex != "^v[0-9]+$" {
		t.Errorf("Headers[2].Regex = %v, want ^v[0-9]+$", match.Headers[2].Regex)
	}
}

func TestGraphQLRouteStatus_Conditions(t *testing.T) {
	status := GraphQLRouteStatus{
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

func TestGraphQLRouteStatus_AppliedGateways(t *testing.T) {
	status := GraphQLRouteStatus{
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

func TestGraphQLRouteList_Items(t *testing.T) {
	list := &GraphQLRouteList{
		Items: []GraphQLRoute{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "graphql-route-1",
					Namespace: "default",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "graphql-route-2",
					Namespace: "default",
				},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Fatalf("Items length = %v, want 2", len(list.Items))
	}
	if list.Items[0].Name != "graphql-route-1" {
		t.Errorf("Items[0].Name = %v, want graphql-route-1", list.Items[0].Name)
	}
}

func TestGraphQLRoute_FullSpec(t *testing.T) {
	introspectionEnabled := true
	route := &GraphQLRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GraphQLRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-graphql-route",
			Namespace: "default",
		},
		Spec: GraphQLRouteSpec{
			Match: []GraphQLRouteMatch{
				{
					Path:          &StringMatch{Exact: "/graphql"},
					OperationType: "query",
					OperationName: &StringMatch{Prefix: "Get"},
					Headers: []GraphQLHeaderMatch{
						{Name: "Authorization", Prefix: "Bearer "},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "graphql-backend", Port: 4000},
					Weight:      100,
				},
			},
			Timeout: Duration("30s"),
			Authentication: &AuthenticationConfig{
				Enabled: true,
			},
			Authorization: &AuthorizationConfig{
				Enabled: true,
			},
			DepthLimit:           10,
			ComplexityLimit:      100,
			IntrospectionEnabled: &introspectionEnabled,
			AllowedOperations:    []string{"query", "mutation", "subscription"},
		},
		Status: GraphQLRouteStatus{
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

	if route.Name != "full-graphql-route" {
		t.Errorf("Name = %v, want full-graphql-route", route.Name)
	}
	if len(route.Spec.Match) != 1 {
		t.Errorf("Spec.Match length = %v, want 1", len(route.Spec.Match))
	}
	if route.Spec.DepthLimit != 10 {
		t.Errorf("Spec.DepthLimit = %v, want 10", route.Spec.DepthLimit)
	}
	if route.Spec.ComplexityLimit != 100 {
		t.Errorf("Spec.ComplexityLimit = %v, want 100", route.Spec.ComplexityLimit)
	}
	if !*route.Spec.IntrospectionEnabled {
		t.Error("Spec.IntrospectionEnabled should be true")
	}
	if len(route.Spec.AllowedOperations) != 3 {
		t.Errorf("Spec.AllowedOperations length = %v, want 3", len(route.Spec.AllowedOperations))
	}
}

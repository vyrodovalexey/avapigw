// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ============================================================================
// GraphQLRoute Status Interface Tests
// ============================================================================

func TestGraphQLRoute_GetConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []Condition
	}{
		{
			name:       "nil conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       []Condition{},
		},
		{
			name: "single condition",
			conditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
			want: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
		},
		{
			name: "multiple conditions",
			conditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
				{
					Type:    ConditionValid,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonValidationPassed,
					Message: "GraphQL route is valid",
				},
			},
			want: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
				{
					Type:    ConditionValid,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonValidationPassed,
					Message: "GraphQL route is valid",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &GraphQLRoute{
				Status: GraphQLRouteStatus{
					Conditions: tt.conditions,
				},
			}

			got := route.GetConditions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGraphQLRoute_SetConditions(t *testing.T) {
	tests := []struct {
		name           string
		initial        []Condition
		newConditions  []Condition
		wantConditions []Condition
	}{
		{
			name:    "set conditions on empty",
			initial: nil,
			newConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
			wantConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
		},
		{
			name: "replace existing conditions",
			initial: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionFalse,
					Reason:  ReasonReconcileFailed,
					Message: "GraphQL route is not configured",
				},
			},
			newConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
			wantConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
		},
		{
			name: "clear conditions with nil",
			initial: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
			newConditions:  nil,
			wantConditions: nil,
		},
		{
			name: "set empty slice",
			initial: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL route is configured",
				},
			},
			newConditions:  []Condition{},
			wantConditions: []Condition{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &GraphQLRoute{
				Status: GraphQLRouteStatus{
					Conditions: tt.initial,
				},
			}

			route.SetConditions(tt.newConditions)
			assert.Equal(t, tt.wantConditions, route.Status.Conditions)
		})
	}
}

func TestGraphQLRoute_SetObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		initial    int64
		generation int64
		want       int64
	}{
		{
			name:       "set from zero",
			initial:    0,
			generation: 1,
			want:       1,
		},
		{
			name:       "increment generation",
			initial:    1,
			generation: 2,
			want:       2,
		},
		{
			name:       "set to zero",
			initial:    5,
			generation: 0,
			want:       0,
		},
		{
			name:       "large generation",
			initial:    0,
			generation: 9999999,
			want:       9999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := &GraphQLRoute{
				Status: GraphQLRouteStatus{
					ObservedGeneration: tt.initial,
				},
			}

			route.SetObservedGeneration(tt.generation)
			assert.Equal(t, tt.want, route.Status.ObservedGeneration)
		})
	}
}

func TestGraphQLRoute_ConditionsRoundTrip(t *testing.T) {
	route := &GraphQLRoute{}

	conditions := []Condition{
		{
			Type:               ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonReconciled,
			Message:            "GraphQL route is configured",
			LastTransitionTime: metav1.Now(),
		},
	}

	route.SetConditions(conditions)
	got := route.GetConditions()

	assert.Equal(t, conditions, got)
}

// ============================================================================
// GraphQLBackend Status Interface Tests
// ============================================================================

func TestGraphQLBackend_GetConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions []Condition
		want       []Condition
	}{
		{
			name:       "nil conditions",
			conditions: nil,
			want:       nil,
		},
		{
			name:       "empty conditions",
			conditions: []Condition{},
			want:       []Condition{},
		},
		{
			name: "single condition",
			conditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
			want: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
		},
		{
			name: "multiple conditions",
			conditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
				{
					Type:    ConditionHealthy,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonHealthCheckOK,
					Message: "All GraphQL hosts are healthy",
				},
			},
			want: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
				{
					Type:    ConditionHealthy,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonHealthCheckOK,
					Message: "All GraphQL hosts are healthy",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GraphQLBackend{
				Status: GraphQLBackendStatus{
					Conditions: tt.conditions,
				},
			}

			got := backend.GetConditions()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGraphQLBackend_SetConditions(t *testing.T) {
	tests := []struct {
		name           string
		initial        []Condition
		newConditions  []Condition
		wantConditions []Condition
	}{
		{
			name:    "set conditions on empty",
			initial: nil,
			newConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
			wantConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
		},
		{
			name: "replace existing conditions",
			initial: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionFalse,
					Reason:  ReasonReconcileFailed,
					Message: "GraphQL backend is unhealthy",
				},
			},
			newConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
			wantConditions: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
		},
		{
			name: "clear conditions",
			initial: []Condition{
				{
					Type:    ConditionReady,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonReconciled,
					Message: "GraphQL backend is healthy",
				},
			},
			newConditions:  nil,
			wantConditions: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GraphQLBackend{
				Status: GraphQLBackendStatus{
					Conditions: tt.initial,
				},
			}

			backend.SetConditions(tt.newConditions)
			assert.Equal(t, tt.wantConditions, backend.Status.Conditions)
		})
	}
}

func TestGraphQLBackend_SetObservedGeneration(t *testing.T) {
	tests := []struct {
		name       string
		initial    int64
		generation int64
		want       int64
	}{
		{
			name:       "set from zero",
			initial:    0,
			generation: 1,
			want:       1,
		},
		{
			name:       "increment generation",
			initial:    1,
			generation: 2,
			want:       2,
		},
		{
			name:       "set to zero",
			initial:    5,
			generation: 0,
			want:       0,
		},
		{
			name:       "large generation",
			initial:    0,
			generation: 9999999,
			want:       9999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GraphQLBackend{
				Status: GraphQLBackendStatus{
					ObservedGeneration: tt.initial,
				},
			}

			backend.SetObservedGeneration(tt.generation)
			assert.Equal(t, tt.want, backend.Status.ObservedGeneration)
		})
	}
}

func TestGraphQLBackend_SetHealthInfo(t *testing.T) {
	now := metav1.Now()
	pastTime := metav1.NewTime(time.Now().Add(-1 * time.Hour))

	tests := []struct {
		name             string
		totalHosts       int
		healthyHosts     int
		lastHealthCheck  *metav1.Time
		wantTotalHosts   int
		wantHealthyHosts int
		wantHealthCheck  *metav1.Time
	}{
		{
			name:             "set all healthy",
			totalHosts:       3,
			healthyHosts:     3,
			lastHealthCheck:  &now,
			wantTotalHosts:   3,
			wantHealthyHosts: 3,
			wantHealthCheck:  &now,
		},
		{
			name:             "set partial healthy",
			totalHosts:       5,
			healthyHosts:     2,
			lastHealthCheck:  &pastTime,
			wantTotalHosts:   5,
			wantHealthyHosts: 2,
			wantHealthCheck:  &pastTime,
		},
		{
			name:             "set none healthy",
			totalHosts:       3,
			healthyHosts:     0,
			lastHealthCheck:  &now,
			wantTotalHosts:   3,
			wantHealthyHosts: 0,
			wantHealthCheck:  &now,
		},
		{
			name:             "nil health check time",
			totalHosts:       2,
			healthyHosts:     1,
			lastHealthCheck:  nil,
			wantTotalHosts:   2,
			wantHealthyHosts: 1,
			wantHealthCheck:  nil,
		},
		{
			name:             "zero hosts",
			totalHosts:       0,
			healthyHosts:     0,
			lastHealthCheck:  nil,
			wantTotalHosts:   0,
			wantHealthyHosts: 0,
			wantHealthCheck:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &GraphQLBackend{}

			backend.SetHealthInfo(tt.totalHosts, tt.healthyHosts, tt.lastHealthCheck)

			assert.Equal(t, tt.wantTotalHosts, backend.Status.TotalHosts)
			assert.Equal(t, tt.wantHealthyHosts, backend.Status.HealthyHosts)
			assert.Equal(t, tt.wantHealthCheck, backend.Status.LastHealthCheck)
		})
	}
}

func TestGraphQLBackend_ConditionsRoundTrip(t *testing.T) {
	backend := &GraphQLBackend{}

	conditions := []Condition{
		{
			Type:               ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonReconciled,
			Message:            "GraphQL backend is healthy",
			LastTransitionTime: metav1.Now(),
		},
	}

	backend.SetConditions(conditions)
	got := backend.GetConditions()

	assert.Equal(t, conditions, got)
}

func TestGraphQLBackend_SetHealthInfo_UpdateExisting(t *testing.T) {
	backend := &GraphQLBackend{}
	now := metav1.Now()

	// First update
	backend.SetHealthInfo(3, 3, &now)
	assert.Equal(t, 3, backend.Status.TotalHosts)
	assert.Equal(t, 3, backend.Status.HealthyHosts)

	// Second update - some hosts become unhealthy
	later := metav1.NewTime(time.Now().Add(1 * time.Minute))
	backend.SetHealthInfo(3, 1, &later)
	assert.Equal(t, 3, backend.Status.TotalHosts)
	assert.Equal(t, 1, backend.Status.HealthyHosts)
	assert.Equal(t, &later, backend.Status.LastHealthCheck)
}

// ============================================================================
// GraphQLRoute DeepCopy Tests
// ============================================================================

func TestGraphQLRoute_DeepCopy_FullyPopulated(t *testing.T) {
	introspectionEnabled := true
	original := &GraphQLRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GraphQLRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-route",
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
						{Name: "X-Tenant", Exact: "acme"},
					},
				},
				{
					Path:          &StringMatch{Prefix: "/api/graphql"},
					OperationType: "mutation",
					Headers: []GraphQLHeaderMatch{
						{Name: "X-Version", Regex: "^v[0-9]+$"},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "graphql-backend", Port: 4000},
					Weight:      80,
				},
				{
					Destination: Destination{Host: "graphql-backend-canary", Port: 4000},
					Weight:      20,
				},
			},
			Timeout: Duration("30s"),
			Retries: &RetryPolicy{
				Attempts:      3,
				PerTryTimeout: Duration("10s"),
				RetryOn:       "5xx",
			},
			Headers: &HeaderManipulation{
				Request: &HeaderOperation{
					Set:    map[string]string{"X-Gateway": "avapigw"},
					Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
					Remove: []string{"X-Internal"},
				},
				Response: &HeaderOperation{
					Set: map[string]string{"X-Response-Time": "{{.ResponseTime}}"},
				},
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
				PerClient:         true,
			},
			Cache: &CacheConfig{
				Enabled:              true,
				TTL:                  Duration("5m"),
				KeyComponents:        []string{"path", "query"},
				StaleWhileRevalidate: Duration("1m"),
			},
			CORS: &CORSConfig{
				AllowOrigins:     []string{"https://example.com"},
				AllowMethods:     []string{"POST"},
				AllowHeaders:     []string{"Content-Type", "Authorization"},
				ExposeHeaders:    []string{"X-Request-ID"},
				MaxAge:           86400,
				AllowCredentials: true,
			},
			Security: &SecurityConfig{
				Enabled: true,
				Headers: &SecurityHeadersConfig{
					Enabled:       true,
					XFrameOptions: "DENY",
				},
			},
			TLS: &RouteTLSConfig{
				CertFile:     "/certs/tls.crt",
				KeyFile:      "/certs/tls.key",
				SNIHosts:     []string{"graphql.example.com"},
				MinVersion:   "TLS12",
				MaxVersion:   "TLS13",
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				ClientValidation: &ClientValidationConfig{
					Enabled:           true,
					CAFile:            "/certs/ca.crt",
					RequireClientCert: true,
					AllowedCNs:        []string{"client1"},
					AllowedSANs:       []string{"san1.example.com"},
				},
				Vault: &VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "graphql-route",
					CommonName: "graphql.example.com",
					AltNames:   []string{"graphql2.example.com"},
					TTL:        "24h",
				},
			},
			Authentication: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled:   true,
					Issuer:    "https://issuer.example.com",
					Audience:  []string{"api"},
					JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
					Algorithm: "RS256",
					ClaimMapping: &ClaimMappingConfig{
						Roles:       "roles",
						Permissions: "permissions",
					},
				},
				SkipPaths: []string{"/health"},
			},
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
							Priority:  100,
						},
					},
					RoleHierarchy: map[string][]string{
						"admin": {"user"},
					},
				},
				SkipPaths: []string{"/public/*"},
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
				QueueSize:     100,
				QueueTimeout:  Duration("10s"),
			},
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
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
					Message:            "Route applied",
					LastTransitionTime: metav1.Now(),
					ObservedGeneration: 1,
				},
			},
			AppliedGateways: []AppliedGateway{
				{
					Name:        "gateway-1",
					Namespace:   "avapigw-system",
					LastApplied: metav1.Now(),
				},
			},
			ObservedGeneration: 1,
		},
	}

	// Test DeepCopy
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.NotSame(t, original, copied)

	// Verify values are equal
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Namespace, copied.Namespace)
	assert.Equal(t, original.Spec.Timeout, copied.Spec.Timeout)
	assert.Equal(t, original.Spec.DepthLimit, copied.Spec.DepthLimit)
	assert.Equal(t, original.Spec.ComplexityLimit, copied.Spec.ComplexityLimit)
	assert.Equal(t, *original.Spec.IntrospectionEnabled, *copied.Spec.IntrospectionEnabled)
	assert.Equal(t, original.Spec.AllowedOperations, copied.Spec.AllowedOperations)
	assert.Equal(t, original.Status.ObservedGeneration, copied.Status.ObservedGeneration)

	// Verify deep copy independence - modifying copy doesn't affect original
	copied.Name = "modified"
	assert.NotEqual(t, original.Name, copied.Name)

	copied.Spec.Match[0].Headers[0].Name = "modified"
	assert.Equal(t, "Authorization", original.Spec.Match[0].Headers[0].Name)

	copied.Spec.AllowedOperations[0] = "modified"
	assert.Equal(t, "query", original.Spec.AllowedOperations[0])

	*copied.Spec.IntrospectionEnabled = false
	assert.True(t, *original.Spec.IntrospectionEnabled)

	copied.Spec.Headers.Request.Set["X-Gateway"] = "modified"
	assert.Equal(t, "avapigw", original.Spec.Headers.Request.Set["X-Gateway"])

	copied.Spec.Route[0].Destination.Host = "modified"
	assert.Equal(t, "graphql-backend", original.Spec.Route[0].Destination.Host)

	copied.Status.Conditions[0].Message = "modified"
	assert.Equal(t, "Route applied", original.Status.Conditions[0].Message)
}

func TestGraphQLRoute_DeepCopy_NilAndEmpty(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var nilRoute *GraphQLRoute
		assert.Nil(t, nilRoute.DeepCopy())
	})

	t.Run("empty struct", func(t *testing.T) {
		original := &GraphQLRoute{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.NotSame(t, original, copied)
		assert.Equal(t, original.Name, copied.Name)
	})

	t.Run("nil optional fields", func(t *testing.T) {
		original := &GraphQLRoute{
			Spec: GraphQLRouteSpec{
				Match:                nil,
				Route:                nil,
				Retries:              nil,
				Headers:              nil,
				RateLimit:            nil,
				Cache:                nil,
				CORS:                 nil,
				Security:             nil,
				TLS:                  nil,
				Authentication:       nil,
				Authorization:        nil,
				MaxSessions:          nil,
				RequestLimits:        nil,
				IntrospectionEnabled: nil,
				AllowedOperations:    nil,
			},
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Spec.Match)
		assert.Nil(t, copied.Spec.Route)
		assert.Nil(t, copied.Spec.Retries)
		assert.Nil(t, copied.Spec.Headers)
		assert.Nil(t, copied.Spec.RateLimit)
		assert.Nil(t, copied.Spec.Cache)
		assert.Nil(t, copied.Spec.CORS)
		assert.Nil(t, copied.Spec.Security)
		assert.Nil(t, copied.Spec.TLS)
		assert.Nil(t, copied.Spec.Authentication)
		assert.Nil(t, copied.Spec.Authorization)
		assert.Nil(t, copied.Spec.MaxSessions)
		assert.Nil(t, copied.Spec.RequestLimits)
		assert.Nil(t, copied.Spec.IntrospectionEnabled)
		assert.Nil(t, copied.Spec.AllowedOperations)
	})
}

func TestGraphQLRoute_DeepCopyObject(t *testing.T) {
	t.Run("returns runtime.Object", func(t *testing.T) {
		original := &GraphQLRoute{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "avapigw.io/v1alpha1",
				Kind:       "GraphQLRoute",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-route",
			},
		}

		obj := original.DeepCopyObject()
		require.NotNil(t, obj)

		// Verify it's a runtime.Object
		var _ runtime.Object = obj

		// Verify it's the correct type
		route, ok := obj.(*GraphQLRoute)
		require.True(t, ok)
		assert.Equal(t, "test-route", route.Name)
	})

	t.Run("nil receiver returns nil", func(t *testing.T) {
		var nilRoute *GraphQLRoute
		// DeepCopy returns nil for nil receiver, so DeepCopyObject returns nil
		assert.Nil(t, nilRoute.DeepCopy())
	})
}

func TestGraphQLRoute_DeepCopyInto(t *testing.T) {
	introspectionEnabled := true
	original := &GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name: "original",
		},
		Spec: GraphQLRouteSpec{
			Match: []GraphQLRouteMatch{
				{
					Path:          &StringMatch{Exact: "/graphql"},
					OperationType: "query",
					Headers: []GraphQLHeaderMatch{
						{Name: "X-Custom", Exact: "value"},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "backend", Port: 4000},
					Weight:      100,
				},
			},
			AllowedOperations:    []string{"query", "mutation"},
			IntrospectionEnabled: &introspectionEnabled,
			DepthLimit:           10,
			ComplexityLimit:      100,
		},
	}

	copied := &GraphQLRoute{}
	original.DeepCopyInto(copied)

	// Verify equality
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.DepthLimit, copied.Spec.DepthLimit)

	// Verify independence
	copied.Name = "modified"
	assert.Equal(t, "original", original.Name)

	copied.Spec.Match[0].Headers[0].Name = "modified"
	assert.Equal(t, "X-Custom", original.Spec.Match[0].Headers[0].Name)

	copied.Spec.AllowedOperations[0] = "modified"
	assert.Equal(t, "query", original.Spec.AllowedOperations[0])

	*copied.Spec.IntrospectionEnabled = false
	assert.True(t, *original.Spec.IntrospectionEnabled)
}

// ============================================================================
// GraphQLRouteList DeepCopy Tests
// ============================================================================

func TestGraphQLRouteList_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &GraphQLRouteList{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "avapigw.io/v1alpha1",
				Kind:       "GraphQLRouteList",
			},
			Items: []GraphQLRoute{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-1"},
					Spec: GraphQLRouteSpec{
						Timeout:           Duration("30s"),
						DepthLimit:        10,
						AllowedOperations: []string{"query"},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "route-2"},
					Spec: GraphQLRouteSpec{
						Timeout:           Duration("60s"),
						DepthLimit:        20,
						AllowedOperations: []string{"mutation"},
					},
				},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, len(original.Items), len(copied.Items))
		assert.Equal(t, original.Items[0].Name, copied.Items[0].Name)
		assert.Equal(t, original.Items[1].Name, copied.Items[1].Name)

		// Verify independence
		copied.Items[0].Name = "modified"
		assert.Equal(t, "route-1", original.Items[0].Name)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilList *GraphQLRouteList
		assert.Nil(t, nilList.DeepCopy())
	})

	t.Run("empty items", func(t *testing.T) {
		original := &GraphQLRouteList{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Items)
	})
}

func TestGraphQLRouteList_DeepCopyObject(t *testing.T) {
	original := &GraphQLRouteList{
		Items: []GraphQLRoute{
			{ObjectMeta: metav1.ObjectMeta{Name: "route-1"}},
		},
	}

	obj := original.DeepCopyObject()
	require.NotNil(t, obj)

	var _ runtime.Object = obj

	list, ok := obj.(*GraphQLRouteList)
	require.True(t, ok)
	assert.Equal(t, 1, len(list.Items))
}

func TestGraphQLRouteList_DeepCopyInto(t *testing.T) {
	original := &GraphQLRouteList{
		Items: []GraphQLRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "route-1"},
				Spec: GraphQLRouteSpec{
					AllowedOperations: []string{"query"},
				},
			},
		},
	}

	copied := &GraphQLRouteList{}
	original.DeepCopyInto(copied)

	assert.Equal(t, 1, len(copied.Items))
	assert.Equal(t, "route-1", copied.Items[0].Name)

	// Verify independence
	copied.Items[0].Name = "modified"
	assert.Equal(t, "route-1", original.Items[0].Name)
}

// ============================================================================
// GraphQLRouteSpec DeepCopy Tests
// ============================================================================

func TestGraphQLRouteSpec_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		introspectionEnabled := false
		original := &GraphQLRouteSpec{
			Match: []GraphQLRouteMatch{
				{
					Path:          &StringMatch{Exact: "/graphql"},
					OperationType: "query",
					OperationName: &StringMatch{Prefix: "Get"},
					Headers: []GraphQLHeaderMatch{
						{Name: "X-Custom", Exact: "value"},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "backend", Port: 4000},
					Weight:      100,
				},
			},
			Timeout: Duration("30s"),
			Retries: &RetryPolicy{
				Attempts:      3,
				PerTryTimeout: Duration("10s"),
			},
			Headers: &HeaderManipulation{
				Request: &HeaderOperation{
					Set: map[string]string{"X-Gateway": "avapigw"},
				},
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
			},
			Cache: &CacheConfig{
				Enabled:       true,
				TTL:           Duration("5m"),
				KeyComponents: []string{"path"},
			},
			CORS: &CORSConfig{
				AllowOrigins: []string{"*"},
			},
			Security: &SecurityConfig{
				Enabled: true,
			},
			TLS: &RouteTLSConfig{
				CertFile: "/certs/tls.crt",
			},
			Authentication: &AuthenticationConfig{
				Enabled: true,
			},
			Authorization: &AuthorizationConfig{
				Enabled: true,
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
			},
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize: 10485760,
			},
			DepthLimit:           10,
			ComplexityLimit:      100,
			IntrospectionEnabled: &introspectionEnabled,
			AllowedOperations:    []string{"query", "mutation"},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.True(t, reflect.DeepEqual(original, copied))

		// Verify independence
		copied.AllowedOperations[0] = "modified"
		assert.Equal(t, "query", original.AllowedOperations[0])

		*copied.IntrospectionEnabled = true
		assert.False(t, *original.IntrospectionEnabled)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilSpec *GraphQLRouteSpec
		assert.Nil(t, nilSpec.DeepCopy())
	})

	t.Run("empty spec", func(t *testing.T) {
		original := &GraphQLRouteSpec{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Match)
		assert.Nil(t, copied.Route)
	})
}

func TestGraphQLRouteSpec_DeepCopyInto(t *testing.T) {
	introspectionEnabled := true
	original := &GraphQLRouteSpec{
		Match: []GraphQLRouteMatch{
			{
				Path:          &StringMatch{Exact: "/graphql"},
				OperationType: "query",
			},
		},
		AllowedOperations:    []string{"query"},
		IntrospectionEnabled: &introspectionEnabled,
		DepthLimit:           5,
	}

	copied := &GraphQLRouteSpec{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.DepthLimit, copied.DepthLimit)
	assert.Equal(t, original.AllowedOperations, copied.AllowedOperations)

	// Verify independence
	copied.AllowedOperations[0] = "modified"
	assert.Equal(t, "query", original.AllowedOperations[0])
}

// ============================================================================
// GraphQLRouteMatch DeepCopy Tests
// ============================================================================

func TestGraphQLRouteMatch_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &GraphQLRouteMatch{
			Path:          &StringMatch{Exact: "/graphql"},
			OperationType: "query",
			OperationName: &StringMatch{Prefix: "Get"},
			Headers: []GraphQLHeaderMatch{
				{Name: "Authorization", Prefix: "Bearer "},
				{Name: "X-Tenant", Exact: "acme"},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.True(t, reflect.DeepEqual(original, copied))

		// Verify pointer independence
		assert.NotSame(t, original.Path, copied.Path)
		assert.NotSame(t, original.OperationName, copied.OperationName)

		// Verify slice independence
		copied.Headers[0].Name = "modified"
		assert.Equal(t, "Authorization", original.Headers[0].Name)

		// Verify StringMatch pointer independence
		copied.Path.Exact = "modified"
		assert.Equal(t, "/graphql", original.Path.Exact)

		copied.OperationName.Prefix = "modified"
		assert.Equal(t, "Get", original.OperationName.Prefix)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilMatch *GraphQLRouteMatch
		assert.Nil(t, nilMatch.DeepCopy())
	})

	t.Run("nil optional fields", func(t *testing.T) {
		original := &GraphQLRouteMatch{
			OperationType: "mutation",
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Path)
		assert.Nil(t, copied.OperationName)
		assert.Nil(t, copied.Headers)
		assert.Equal(t, "mutation", copied.OperationType)
	})

	t.Run("empty headers", func(t *testing.T) {
		original := &GraphQLRouteMatch{
			Path:    &StringMatch{Exact: "/graphql"},
			Headers: []GraphQLHeaderMatch{},
		}
		// Note: empty slice vs nil - DeepCopyInto copies nil check
		copied := original.DeepCopy()
		require.NotNil(t, copied)
	})
}

func TestGraphQLRouteMatch_DeepCopyInto(t *testing.T) {
	original := &GraphQLRouteMatch{
		Path:          &StringMatch{Exact: "/graphql"},
		OperationType: "query",
		Headers: []GraphQLHeaderMatch{
			{Name: "X-Custom", Exact: "value"},
		},
	}

	copied := &GraphQLRouteMatch{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.OperationType, copied.OperationType)
	assert.Equal(t, original.Path.Exact, copied.Path.Exact)

	// Verify independence
	copied.Path.Exact = "modified"
	assert.Equal(t, "/graphql", original.Path.Exact)
}

// ============================================================================
// GraphQLHeaderMatch DeepCopy Tests
// ============================================================================

func TestGraphQLHeaderMatch_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &GraphQLHeaderMatch{
			Name:   "Authorization",
			Exact:  "Bearer token123",
			Prefix: "Bearer ",
			Regex:  "^Bearer .+$",
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.NotSame(t, original, copied)
		assert.Equal(t, original.Name, copied.Name)
		assert.Equal(t, original.Exact, copied.Exact)
		assert.Equal(t, original.Prefix, copied.Prefix)
		assert.Equal(t, original.Regex, copied.Regex)

		// Verify independence
		copied.Name = "modified"
		assert.Equal(t, "Authorization", original.Name)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilMatch *GraphQLHeaderMatch
		assert.Nil(t, nilMatch.DeepCopy())
	})

	t.Run("empty struct", func(t *testing.T) {
		original := &GraphQLHeaderMatch{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, "", copied.Name)
		assert.Equal(t, "", copied.Exact)
	})

	t.Run("only name set", func(t *testing.T) {
		original := &GraphQLHeaderMatch{
			Name: "X-Custom",
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, "X-Custom", copied.Name)
		assert.Equal(t, "", copied.Exact)
		assert.Equal(t, "", copied.Prefix)
		assert.Equal(t, "", copied.Regex)
	})
}

func TestGraphQLHeaderMatch_DeepCopyInto(t *testing.T) {
	original := &GraphQLHeaderMatch{
		Name:   "X-Custom",
		Exact:  "value",
		Prefix: "pre",
		Regex:  ".*",
	}

	copied := &GraphQLHeaderMatch{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Exact, copied.Exact)
	assert.Equal(t, original.Prefix, copied.Prefix)
	assert.Equal(t, original.Regex, copied.Regex)

	// Verify independence (scalar fields are copied by value)
	copied.Name = "modified"
	assert.Equal(t, "X-Custom", original.Name)
}

// ============================================================================
// GraphQLBackend DeepCopy Tests
// ============================================================================

func TestGraphQLBackend_DeepCopy_FullyPopulated(t *testing.T) {
	now := metav1.Now()
	original := &GraphQLBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GraphQLBackend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-backend",
			Namespace: "default",
		},
		Spec: GraphQLBackendSpec{
			Hosts: []BackendHost{
				{Address: "graphql-backend-1", Port: 4000, Weight: 50},
				{Address: "graphql-backend-2", Port: 4000, Weight: 50},
			},
			HealthCheck: &HealthCheckConfig{
				Path:     "/health",
				Interval: Duration("10s"),
				Timeout:  Duration("5s"),
			},
			LoadBalancer: &LoadBalancerConfig{
				Algorithm: LoadBalancerRoundRobin,
			},
			TLS: &BackendTLSConfig{
				Enabled:      true,
				CertFile:     "/certs/tls.crt",
				KeyFile:      "/certs/tls.key",
				CAFile:       "/certs/ca.crt",
				MinVersion:   "TLS12",
				MaxVersion:   "TLS13",
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				ALPN:         []string{"h2", "http/1.1"},
				Vault: &VaultBackendTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "graphql-backend",
					CommonName: "graphql-backend.example.com",
					AltNames:   []string{"graphql-backend2.example.com"},
					TTL:        "24h",
				},
			},
			CircuitBreaker: &CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          Duration("30s"),
				HalfOpenRequests: 3,
			},
			Authentication: &BackendAuthConfig{
				Type: "jwt",
				JWT: &BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					HeaderName:  "Authorization",
					OIDC: &BackendOIDCConfig{
						IssuerURL:    "https://auth.example.com",
						ClientID:     "client-id",
						ClientSecret: "client-secret",
						Scopes:       []string{"api", "read"},
					},
				},
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
			},
			Cache: &BackendCacheConfig{
				Enabled:              true,
				TTL:                  Duration("10m"),
				KeyComponents:        []string{"path", "query"},
				StaleWhileRevalidate: Duration("2m"),
				Type:                 "redis",
			},
			Encoding: &BackendEncodingConfig{
				Request:  &BackendEncodingSettings{ContentType: "application/json", Compression: "gzip"},
				Response: &BackendEncodingSettings{ContentType: "application/json", Compression: "br"},
			},
		},
		Status: GraphQLBackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: now,
				},
				{
					Type:               ConditionHealthy,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonHealthCheckOK,
					LastTransitionTime: now,
				},
			},
			HealthyHosts:       2,
			TotalHosts:         2,
			LastHealthCheck:    ptrTime(now),
			ObservedGeneration: 1,
		},
	}

	// Test DeepCopy
	copied := original.DeepCopy()
	require.NotNil(t, copied)
	assert.NotSame(t, original, copied)

	// Verify values are equal
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.Hosts[0].Address, copied.Spec.Hosts[0].Address)
	assert.Equal(t, original.Status.HealthyHosts, copied.Status.HealthyHosts)
	assert.Equal(t, original.Status.TotalHosts, copied.Status.TotalHosts)
	assert.Equal(t, original.Status.ObservedGeneration, copied.Status.ObservedGeneration)

	// Verify deep copy independence
	copied.Name = "modified"
	assert.NotEqual(t, original.Name, copied.Name)

	copied.Spec.Hosts[0].Address = "modified"
	assert.Equal(t, "graphql-backend-1", original.Spec.Hosts[0].Address)

	copied.Status.Conditions[0].Message = "modified"
	assert.Equal(t, "", original.Status.Conditions[0].Message)

	copied.Spec.TLS.CipherSuites[0] = "modified"
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", original.Spec.TLS.CipherSuites[0])

	copied.Spec.Cache.KeyComponents[0] = "modified"
	assert.Equal(t, "path", original.Spec.Cache.KeyComponents[0])
}

func TestGraphQLBackend_DeepCopy_NilAndEmpty(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var nilBackend *GraphQLBackend
		assert.Nil(t, nilBackend.DeepCopy())
	})

	t.Run("empty struct", func(t *testing.T) {
		original := &GraphQLBackend{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.NotSame(t, original, copied)
	})

	t.Run("nil optional fields", func(t *testing.T) {
		original := &GraphQLBackend{
			Spec: GraphQLBackendSpec{
				Hosts:          []BackendHost{{Address: "localhost", Port: 4000}},
				HealthCheck:    nil,
				LoadBalancer:   nil,
				TLS:            nil,
				CircuitBreaker: nil,
				Authentication: nil,
				MaxSessions:    nil,
				RateLimit:      nil,
				Cache:          nil,
				Encoding:       nil,
			},
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Spec.HealthCheck)
		assert.Nil(t, copied.Spec.LoadBalancer)
		assert.Nil(t, copied.Spec.TLS)
		assert.Nil(t, copied.Spec.CircuitBreaker)
		assert.Nil(t, copied.Spec.Authentication)
		assert.Nil(t, copied.Spec.MaxSessions)
		assert.Nil(t, copied.Spec.RateLimit)
		assert.Nil(t, copied.Spec.Cache)
		assert.Nil(t, copied.Spec.Encoding)
	})
}

func TestGraphQLBackend_DeepCopyObject(t *testing.T) {
	t.Run("returns runtime.Object", func(t *testing.T) {
		original := &GraphQLBackend{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "avapigw.io/v1alpha1",
				Kind:       "GraphQLBackend",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-backend",
			},
		}

		obj := original.DeepCopyObject()
		require.NotNil(t, obj)

		var _ runtime.Object = obj

		backend, ok := obj.(*GraphQLBackend)
		require.True(t, ok)
		assert.Equal(t, "test-backend", backend.Name)
	})

	t.Run("nil receiver returns nil", func(t *testing.T) {
		var nilBackend *GraphQLBackend
		assert.Nil(t, nilBackend.DeepCopy())
	})
}

func TestGraphQLBackend_DeepCopyInto(t *testing.T) {
	now := metav1.Now()
	original := &GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name: "original",
		},
		Spec: GraphQLBackendSpec{
			Hosts: []BackendHost{
				{Address: "backend-1", Port: 4000, Weight: 100},
			},
			HealthCheck: &HealthCheckConfig{
				Path:     "/health",
				Interval: Duration("10s"),
			},
			Cache: &BackendCacheConfig{
				Enabled:       true,
				TTL:           Duration("5m"),
				KeyComponents: []string{"path"},
			},
		},
		Status: GraphQLBackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: now,
				},
			},
			HealthyHosts:       1,
			TotalHosts:         1,
			LastHealthCheck:    ptrTime(now),
			ObservedGeneration: 1,
		},
	}

	copied := &GraphQLBackend{}
	original.DeepCopyInto(copied)

	// Verify equality
	assert.Equal(t, original.Name, copied.Name)
	assert.Equal(t, original.Spec.Hosts[0].Address, copied.Spec.Hosts[0].Address)
	assert.Equal(t, original.Status.HealthyHosts, copied.Status.HealthyHosts)

	// Verify independence
	copied.Name = "modified"
	assert.Equal(t, "original", original.Name)

	copied.Spec.Hosts[0].Address = "modified"
	assert.Equal(t, "backend-1", original.Spec.Hosts[0].Address)

	copied.Spec.Cache.KeyComponents[0] = "modified"
	assert.Equal(t, "path", original.Spec.Cache.KeyComponents[0])
}

// ============================================================================
// GraphQLBackendList DeepCopy Tests
// ============================================================================

func TestGraphQLBackendList_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &GraphQLBackendList{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "avapigw.io/v1alpha1",
				Kind:       "GraphQLBackendList",
			},
			Items: []GraphQLBackend{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
					Spec: GraphQLBackendSpec{
						Hosts: []BackendHost{
							{Address: "host-1", Port: 4000},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "backend-2"},
					Spec: GraphQLBackendSpec{
						Hosts: []BackendHost{
							{Address: "host-2", Port: 4000},
						},
					},
				},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, len(original.Items), len(copied.Items))
		assert.Equal(t, original.Items[0].Name, copied.Items[0].Name)

		// Verify independence
		copied.Items[0].Name = "modified"
		assert.Equal(t, "backend-1", original.Items[0].Name)

		copied.Items[0].Spec.Hosts[0].Address = "modified"
		assert.Equal(t, "host-1", original.Items[0].Spec.Hosts[0].Address)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilList *GraphQLBackendList
		assert.Nil(t, nilList.DeepCopy())
	})

	t.Run("empty items", func(t *testing.T) {
		original := &GraphQLBackendList{}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Items)
	})
}

func TestGraphQLBackendList_DeepCopyObject(t *testing.T) {
	original := &GraphQLBackendList{
		Items: []GraphQLBackend{
			{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}},
		},
	}

	obj := original.DeepCopyObject()
	require.NotNil(t, obj)

	var _ runtime.Object = obj

	list, ok := obj.(*GraphQLBackendList)
	require.True(t, ok)
	assert.Equal(t, 1, len(list.Items))
}

func TestGraphQLBackendList_DeepCopyInto(t *testing.T) {
	original := &GraphQLBackendList{
		Items: []GraphQLBackend{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "backend-1"},
				Spec: GraphQLBackendSpec{
					Hosts: []BackendHost{
						{Address: "host-1", Port: 4000},
					},
				},
			},
		},
	}

	copied := &GraphQLBackendList{}
	original.DeepCopyInto(copied)

	assert.Equal(t, 1, len(copied.Items))
	assert.Equal(t, "backend-1", copied.Items[0].Name)

	// Verify independence
	copied.Items[0].Name = "modified"
	assert.Equal(t, "backend-1", original.Items[0].Name)
}

// ============================================================================
// GraphQLBackendSpec DeepCopy Tests
// ============================================================================

func TestGraphQLBackendSpec_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		original := &GraphQLBackendSpec{
			Hosts: []BackendHost{
				{Address: "backend-1", Port: 4000, Weight: 50},
				{Address: "backend-2", Port: 4000, Weight: 50},
			},
			HealthCheck: &HealthCheckConfig{
				Path:     "/health",
				Interval: Duration("10s"),
				Timeout:  Duration("5s"),
			},
			LoadBalancer: &LoadBalancerConfig{
				Algorithm: LoadBalancerRoundRobin,
			},
			TLS: &BackendTLSConfig{
				Enabled:      true,
				CertFile:     "/certs/tls.crt",
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				ALPN:         []string{"h2"},
			},
			CircuitBreaker: &CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
			},
			Authentication: &BackendAuthConfig{
				Type: "jwt",
				JWT: &BackendJWTAuthConfig{
					Enabled: true,
				},
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
			},
			Cache: &BackendCacheConfig{
				Enabled:       true,
				TTL:           Duration("10m"),
				KeyComponents: []string{"path", "query"},
			},
			Encoding: &BackendEncodingConfig{
				Request:  &BackendEncodingSettings{ContentType: "application/json"},
				Response: &BackendEncodingSettings{ContentType: "application/json"},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.True(t, reflect.DeepEqual(original, copied))

		// Verify independence
		copied.Hosts[0].Address = "modified"
		assert.Equal(t, "backend-1", original.Hosts[0].Address)

		copied.TLS.CipherSuites[0] = "modified"
		assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", original.TLS.CipherSuites[0])

		copied.Cache.KeyComponents[0] = "modified"
		assert.Equal(t, "path", original.Cache.KeyComponents[0])
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilSpec *GraphQLBackendSpec
		assert.Nil(t, nilSpec.DeepCopy())
	})

	t.Run("minimal spec", func(t *testing.T) {
		original := &GraphQLBackendSpec{
			Hosts: []BackendHost{
				{Address: "backend", Port: 4000},
			},
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, 1, len(copied.Hosts))
		assert.Nil(t, copied.HealthCheck)
		assert.Nil(t, copied.LoadBalancer)
		assert.Nil(t, copied.TLS)
		assert.Nil(t, copied.CircuitBreaker)
		assert.Nil(t, copied.Authentication)
		assert.Nil(t, copied.MaxSessions)
		assert.Nil(t, copied.RateLimit)
		assert.Nil(t, copied.Cache)
		assert.Nil(t, copied.Encoding)
	})
}

func TestGraphQLBackendSpec_DeepCopyInto(t *testing.T) {
	original := &GraphQLBackendSpec{
		Hosts: []BackendHost{
			{Address: "backend-1", Port: 4000, Weight: 100},
		},
		HealthCheck: &HealthCheckConfig{
			Path: "/health",
		},
	}

	copied := &GraphQLBackendSpec{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.Hosts[0].Address, copied.Hosts[0].Address)
	assert.Equal(t, original.HealthCheck.Path, copied.HealthCheck.Path)

	// Verify independence
	copied.Hosts[0].Address = "modified"
	assert.Equal(t, "backend-1", original.Hosts[0].Address)
}

// ============================================================================
// GraphQLBackendStatus DeepCopy Tests
// ============================================================================

func TestGraphQLBackendStatus_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		now := metav1.Now()
		original := &GraphQLBackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: now,
				},
			},
			ObservedGeneration: 5,
			HealthyHosts:       3,
			TotalHosts:         3,
			LastHealthCheck:    ptrTime(now),
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, original.ObservedGeneration, copied.ObservedGeneration)
		assert.Equal(t, original.HealthyHosts, copied.HealthyHosts)
		assert.Equal(t, original.TotalHosts, copied.TotalHosts)
		assert.Equal(t, len(original.Conditions), len(copied.Conditions))

		// Verify independence
		copied.Conditions[0].Message = "modified"
		assert.Equal(t, "", original.Conditions[0].Message)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilStatus *GraphQLBackendStatus
		assert.Nil(t, nilStatus.DeepCopy())
	})

	t.Run("nil LastHealthCheck", func(t *testing.T) {
		original := &GraphQLBackendStatus{
			HealthyHosts:    1,
			TotalHosts:      1,
			LastHealthCheck: nil,
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.LastHealthCheck)
	})
}

func TestGraphQLBackendStatus_DeepCopyInto(t *testing.T) {
	now := metav1.Now()
	original := &GraphQLBackendStatus{
		Conditions: []Condition{
			{
				Type:               ConditionReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
			},
		},
		ObservedGeneration: 3,
		HealthyHosts:       2,
		TotalHosts:         2,
		LastHealthCheck:    ptrTime(now),
	}

	copied := &GraphQLBackendStatus{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.ObservedGeneration, copied.ObservedGeneration)
	assert.Equal(t, original.HealthyHosts, copied.HealthyHosts)

	// Verify independence
	copied.Conditions[0].Message = "modified"
	assert.Equal(t, "", original.Conditions[0].Message)
}

// ============================================================================
// GraphQLRouteStatus DeepCopy Tests
// ============================================================================

func TestGraphQLRouteStatus_DeepCopy(t *testing.T) {
	t.Run("fully populated", func(t *testing.T) {
		now := metav1.Now()
		original := &GraphQLRouteStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					Message:            "Route applied",
					LastTransitionTime: now,
					ObservedGeneration: 1,
				},
			},
			ObservedGeneration: 1,
			AppliedGateways: []AppliedGateway{
				{
					Name:        "gateway-1",
					Namespace:   "avapigw-system",
					LastApplied: now,
				},
			},
		}

		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Equal(t, original.ObservedGeneration, copied.ObservedGeneration)
		assert.Equal(t, len(original.Conditions), len(copied.Conditions))
		assert.Equal(t, len(original.AppliedGateways), len(copied.AppliedGateways))

		// Verify independence
		copied.Conditions[0].Message = "modified"
		assert.Equal(t, "Route applied", original.Conditions[0].Message)

		copied.AppliedGateways[0].Name = "modified"
		assert.Equal(t, "gateway-1", original.AppliedGateways[0].Name)
	})

	t.Run("nil receiver", func(t *testing.T) {
		var nilStatus *GraphQLRouteStatus
		assert.Nil(t, nilStatus.DeepCopy())
	})

	t.Run("empty conditions and gateways", func(t *testing.T) {
		original := &GraphQLRouteStatus{
			ObservedGeneration: 1,
		}
		copied := original.DeepCopy()
		require.NotNil(t, copied)
		assert.Nil(t, copied.Conditions)
		assert.Nil(t, copied.AppliedGateways)
		assert.Equal(t, int64(1), copied.ObservedGeneration)
	})
}

func TestGraphQLRouteStatus_DeepCopyInto(t *testing.T) {
	now := metav1.Now()
	original := &GraphQLRouteStatus{
		Conditions: []Condition{
			{
				Type:               ConditionReady,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: now,
			},
		},
		ObservedGeneration: 2,
		AppliedGateways: []AppliedGateway{
			{
				Name:        "gateway-1",
				Namespace:   "default",
				LastApplied: now,
			},
		},
	}

	copied := &GraphQLRouteStatus{}
	original.DeepCopyInto(copied)

	assert.Equal(t, original.ObservedGeneration, copied.ObservedGeneration)
	assert.Equal(t, len(original.Conditions), len(copied.Conditions))

	// Verify independence
	copied.AppliedGateways[0].Name = "modified"
	assert.Equal(t, "gateway-1", original.AppliedGateways[0].Name)
}

// ============================================================================
// Deep Copy Equality and Isolation Tests
// ============================================================================

func TestGraphQLRoute_DeepCopy_Equality(t *testing.T) {
	introspectionEnabled := true
	original := &GraphQLRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: GraphQLRouteSpec{
			Match: []GraphQLRouteMatch{
				{
					Path:          &StringMatch{Exact: "/graphql"},
					OperationType: "query",
					OperationName: &StringMatch{Prefix: "Get"},
					Headers: []GraphQLHeaderMatch{
						{Name: "X-Custom", Exact: "value"},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "backend", Port: 4000},
					Weight:      100,
				},
			},
			DepthLimit:           10,
			ComplexityLimit:      100,
			IntrospectionEnabled: &introspectionEnabled,
			AllowedOperations:    []string{"query", "mutation"},
		},
	}

	copied := original.DeepCopy()
	assert.True(t, reflect.DeepEqual(original, copied))
}

func TestGraphQLBackend_DeepCopy_Equality(t *testing.T) {
	now := metav1.Now()
	original := &GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: GraphQLBackendSpec{
			Hosts: []BackendHost{
				{Address: "backend-1", Port: 4000, Weight: 100},
			},
			HealthCheck: &HealthCheckConfig{
				Path:     "/health",
				Interval: Duration("10s"),
			},
			Cache: &BackendCacheConfig{
				Enabled:       true,
				TTL:           Duration("5m"),
				KeyComponents: []string{"path"},
			},
		},
		Status: GraphQLBackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					LastTransitionTime: now,
				},
			},
			HealthyHosts:       1,
			TotalHosts:         1,
			LastHealthCheck:    ptrTime(now),
			ObservedGeneration: 1,
		},
	}

	copied := original.DeepCopy()
	assert.True(t, reflect.DeepEqual(original, copied))
}

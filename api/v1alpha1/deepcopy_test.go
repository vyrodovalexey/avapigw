// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestAPIRoute_DeepCopy tests the DeepCopy methods for APIRoute
func TestAPIRoute_DeepCopy(t *testing.T) {
	original := &APIRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "APIRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: APIRouteSpec{
			Match: []RouteMatch{
				{
					URI: &URIMatch{
						Prefix: "/api/v1",
					},
					Methods: []string{"GET", "POST"},
					Headers: []HeaderMatch{
						{Name: "X-Custom", Exact: "value"},
					},
					QueryParams: []QueryParamMatch{
						{Name: "version", Exact: "v1"},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "backend", Port: 8080},
					Weight:      100,
				},
			},
			Timeout: Duration("30s"),
			Retries: &RetryPolicy{
				Attempts:      3,
				PerTryTimeout: Duration("10s"),
			},
			Redirect: &RedirectConfig{
				URI:  "/new-path",
				Code: 301,
			},
			Rewrite: &RewriteConfig{
				URI:       "/internal",
				Authority: "internal.example.com",
			},
			DirectResponse: &DirectResponseConfig{
				Status:  200,
				Body:    `{"status":"ok"}`,
				Headers: map[string]string{"Content-Type": "application/json"},
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
			Mirror: &MirrorConfig{
				Destination: Destination{Host: "mirror", Port: 8080},
				Percentage:  10,
			},
			Fault: &FaultInjection{
				Delay: &FaultDelay{
					FixedDelay: Duration("100ms"),
					Percentage: 10,
				},
				Abort: &FaultAbort{
					HTTPStatus: 503,
					Percentage: 5,
				},
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
				PerClient:         true,
			},
			Transform: &TransformConfig{
				Request: &RequestTransform{
					Template: `{"wrapped": {{.Body}}}`,
				},
				Response: &ResponseTransform{
					AllowFields:   []string{"id", "name"},
					DenyFields:    []string{"password"},
					FieldMappings: map[string]string{"created_at": "createdAt"},
				},
			},
			Cache: &CacheConfig{
				Enabled:              true,
				TTL:                  Duration("5m"),
				KeyComponents:        []string{"path", "query"},
				StaleWhileRevalidate: Duration("1m"),
			},
			Encoding: &EncodingConfig{
				Request:  &EncodingSettings{ContentType: "application/json"},
				Response: &EncodingSettings{ContentType: "application/json"},
			},
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
			},
			CORS: &CORSConfig{
				AllowOrigins:     []string{"https://example.com"},
				AllowMethods:     []string{"GET", "POST"},
				AllowHeaders:     []string{"Content-Type"},
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
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
				QueueSize:     100,
				QueueTimeout:  Duration("10s"),
			},
			TLS: &RouteTLSConfig{
				CertFile:     "/certs/tls.crt",
				KeyFile:      "/certs/tls.key",
				SNIHosts:     []string{"api.example.com"},
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
					Role:       "api-route",
					CommonName: "api.example.com",
					AltNames:   []string{"api2.example.com"},
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
						Groups:      "groups",
						Scopes:      "scope",
						Email:       "email",
						Name:        "name",
					},
				},
				APIKey: &APIKeyAuthConfig{
					Enabled:       true,
					Header:        "X-API-Key",
					HashAlgorithm: "sha256",
				},
				MTLS: &MTLSAuthConfig{
					Enabled:         true,
					CAFile:          "/certs/ca.crt",
					ExtractIdentity: "cn",
					AllowedCNs:      []string{"client1"},
					AllowedOUs:      []string{"engineering"},
				},
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							Name:         "keycloak",
							IssuerURL:    "https://keycloak.example.com/realms/myrealm",
							ClientID:     "my-client",
							ClientSecret: "my-secret",
							ClientSecretRef: &SecretKeySelector{
								Name: "oidc-secret",
								Key:  "client-secret",
							},
							Scopes: []string{"openid", "profile"},
						},
					},
				},
				AllowAnonymous: true,
				SkipPaths:      []string{"/health", "/metrics"},
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
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Name:       "owner-policy",
							Expression: "request.user == resource.owner",
							Resources:  []string{"/api/*"},
							Actions:    []string{"GET", "PUT"},
							Effect:     "allow",
							Priority:   50,
						},
					},
				},
				External: &ExternalAuthzConfig{
					Enabled: true,
					OPA: &OPAAuthzConfig{
						URL:    "http://opa:8181/v1/data/authz/allow",
						Policy: "authz/allow",
						Headers: map[string]string{
							"X-Custom": "value",
						},
					},
					Timeout:  Duration("5s"),
					FailOpen: false,
				},
				SkipPaths: []string{"/public/*"},
				Cache: &AuthzCacheConfig{
					Enabled: true,
					TTL:     Duration("5m"),
					MaxSize: 1000,
					Type:    "memory",
				},
			},
		},
		Status: APIRouteStatus{
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
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	// Verify it's a different object
	if copied == original {
		t.Error("DeepCopy returned same pointer")
	}

	// Verify values are equal
	if copied.Name != original.Name {
		t.Errorf("Name mismatch: got %v, want %v", copied.Name, original.Name)
	}

	// Modify copied and verify original is unchanged
	copied.Name = "modified"
	if original.Name == "modified" {
		t.Error("Modifying copy affected original")
	}

	// Test DeepCopyObject
	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	// Test nil DeepCopy
	var nilRoute *APIRoute
	if nilRoute.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestAPIRouteList_DeepCopy tests the DeepCopy methods for APIRouteList
func TestAPIRouteList_DeepCopy(t *testing.T) {
	original := &APIRouteList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "APIRouteList",
		},
		Items: []APIRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "route-1"},
				Spec:       APIRouteSpec{Timeout: Duration("30s")},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "route-2"},
				Spec:       APIRouteSpec{Timeout: Duration("60s")},
			},
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	if len(copied.Items) != len(original.Items) {
		t.Errorf("Items length mismatch: got %v, want %v", len(copied.Items), len(original.Items))
	}

	// Test DeepCopyObject
	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	// Test nil DeepCopy
	var nilList *APIRouteList
	if nilList.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestBackend_DeepCopy tests the DeepCopy methods for Backend
func TestBackend_DeepCopy(t *testing.T) {
	original := &Backend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "Backend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "default",
		},
		Spec: BackendSpec{
			Hosts: []BackendHost{
				{Address: "backend-1", Port: 8080, Weight: 50},
				{Address: "backend-2", Port: 8080, Weight: 50},
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
					Role:       "backend",
					CommonName: "backend.example.com",
					AltNames:   []string{"backend2.example.com"},
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
						ClientSecretRef: &SecretKeySelector{
							Name: "oidc-secret",
							Key:  "client-secret",
						},
						Scopes: []string{"api", "read"},
					},
				},
				Basic: &BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
				},
				MTLS: &BackendMTLSAuthConfig{
					Enabled:  true,
					CertFile: "/certs/client.crt",
					KeyFile:  "/certs/client.key",
					Vault: &VaultBackendTLSConfig{
						Enabled:  true,
						PKIMount: "pki",
						Role:     "client",
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
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
			},
			Transform: &BackendTransformConfig{
				Request: &BackendRequestTransform{
					Template: `{"wrapped": {{.Body}}}`,
					Headers: &HeaderOperation{
						Set:    map[string]string{"X-Gateway": "avapigw"},
						Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
						Remove: []string{"X-Internal"},
					},
				},
				Response: &BackendResponseTransform{
					AllowFields:   []string{"id", "name"},
					DenyFields:    []string{"password"},
					FieldMappings: map[string]string{"created_at": "createdAt"},
					Headers: &HeaderOperation{
						Set: map[string]string{"X-Response-Time": "{{.ResponseTime}}"},
					},
				},
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
		Status: BackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: metav1.Now(),
				},
			},
			HealthyHosts:       2,
			TotalHosts:         2,
			LastHealthCheck:    ptrTime(metav1.Now()),
			ObservedGeneration: 1,
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	if copied == original {
		t.Error("DeepCopy returned same pointer")
	}

	// Test DeepCopyObject
	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	// Test nil DeepCopy
	var nilBackend *Backend
	if nilBackend.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestBackendList_DeepCopy tests the DeepCopy methods for BackendList
func TestBackendList_DeepCopy(t *testing.T) {
	original := &BackendList{
		Items: []Backend{
			{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "backend-2"}},
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	var nilList *BackendList
	if nilList.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestGRPCRoute_DeepCopy tests the DeepCopy methods for GRPCRoute
func TestGRPCRoute_DeepCopy(t *testing.T) {
	original := &GRPCRoute{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCRoute",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-route",
			Namespace: "default",
		},
		Spec: GRPCRouteSpec{
			Match: []GRPCRouteMatch{
				{
					Service: &StringMatch{Exact: "myservice.v1.MyService"},
					Method:  &StringMatch{Exact: "GetUser"},
					Metadata: []MetadataMatch{
						{Name: "x-custom", Exact: "value"},
					},
				},
			},
			Route: []RouteDestination{
				{
					Destination: Destination{Host: "grpc-backend", Port: 9090},
					Weight:      100,
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
			Headers: &HeaderManipulation{
				Request: &HeaderOperation{
					Set: map[string]string{"x-gateway": "avapigw"},
				},
			},
			Mirror: &MirrorConfig{
				Destination: Destination{Host: "mirror", Port: 9090},
				Percentage:  10,
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
			},
			Transform: &GRPCTransformConfig{
				FieldMask: &FieldMaskConfig{
					Paths: []string{"user.id", "user.name"},
				},
				Metadata: &MetadataManipulation{
					Static:  map[string]string{"x-source": "gateway"},
					Dynamic: map[string]string{"x-request-id": "{{.RequestID}}"},
				},
			},
			Cache: &CacheConfig{
				Enabled:       true,
				TTL:           Duration("5m"),
				KeyComponents: []string{"service", "method"},
			},
			Encoding: &EncodingConfig{
				Request:  &EncodingSettings{ContentType: "application/grpc"},
				Response: &EncodingSettings{ContentType: "application/grpc"},
			},
			CORS: &CORSConfig{
				AllowOrigins: []string{"*"},
				AllowMethods: []string{"POST"},
			},
			Security: &SecurityConfig{
				Enabled: true,
			},
			TLS: &RouteTLSConfig{
				CertFile: "/certs/tls.crt",
				KeyFile:  "/certs/tls.key",
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 1000,
			},
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize: 10485760,
			},
			Authentication: &AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled: true,
					JWKSURL: "https://issuer.example.com/.well-known/jwks.json",
				},
			},
			Authorization: &AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &RBACConfig{
					Enabled: true,
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

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	if copied == original {
		t.Error("DeepCopy returned same pointer")
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	var nilRoute *GRPCRoute
	if nilRoute.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestGRPCRouteList_DeepCopy tests the DeepCopy methods for GRPCRouteList
func TestGRPCRouteList_DeepCopy(t *testing.T) {
	original := &GRPCRouteList{
		Items: []GRPCRoute{
			{ObjectMeta: metav1.ObjectMeta{Name: "route-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "route-2"}},
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	var nilList *GRPCRouteList
	if nilList.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestGRPCBackend_DeepCopy tests the DeepCopy methods for GRPCBackend
func TestGRPCBackend_DeepCopy(t *testing.T) {
	original := &GRPCBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCBackend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "default",
		},
		Spec: GRPCBackendSpec{
			Hosts: []BackendHost{
				{Address: "grpc-backend-1", Port: 9090, Weight: 50},
				{Address: "grpc-backend-2", Port: 9090, Weight: 50},
			},
			HealthCheck: &GRPCHealthCheckConfig{
				Service:  "grpc.health.v1.Health",
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
				CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
				ALPN:         []string{"h2"},
			},
			ConnectionPool: &GRPCConnectionPoolConfig{
				MaxIdleConns:    10,
				MaxConnsPerHost: 100,
				IdleConnTimeout: Duration("5m"),
			},
			CircuitBreaker: &CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   Duration("30s"),
			},
			Authentication: &BackendAuthConfig{
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
			Transform: &GRPCBackendTransformConfig{
				FieldMask: &GRPCFieldMaskConfig{
					Paths: []string{"user.id", "user.name"},
				},
				Metadata: &GRPCMetadataManipulation{
					Static:  map[string]string{"x-source": "gateway"},
					Dynamic: map[string]string{"x-request-id": "{{.RequestID}}"},
				},
			},
			Cache: &BackendCacheConfig{
				Enabled:       true,
				TTL:           Duration("10m"),
				KeyComponents: []string{"service", "method"},
			},
			Encoding: &BackendEncodingConfig{
				Request:  &BackendEncodingSettings{ContentType: "application/grpc"},
				Response: &BackendEncodingSettings{ContentType: "application/grpc"},
			},
		},
		Status: GRPCBackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: metav1.Now(),
				},
			},
			HealthyHosts:       2,
			TotalHosts:         2,
			LastHealthCheck:    ptrTime(metav1.Now()),
			ObservedGeneration: 1,
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	if copied == original {
		t.Error("DeepCopy returned same pointer")
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	var nilBackend *GRPCBackend
	if nilBackend.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestGRPCBackendList_DeepCopy tests the DeepCopy methods for GRPCBackendList
func TestGRPCBackendList_DeepCopy(t *testing.T) {
	original := &GRPCBackendList{
		Items: []GRPCBackend{
			{ObjectMeta: metav1.ObjectMeta{Name: "backend-1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "backend-2"}},
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	obj := original.DeepCopyObject()
	if obj == nil {
		t.Fatal("DeepCopyObject returned nil")
	}

	var nilList *GRPCBackendList
	if nilList.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

// TestCommonTypes_DeepCopy tests DeepCopy for common types
func TestCommonTypes_DeepCopy(t *testing.T) {
	t.Run("Condition", func(t *testing.T) {
		original := &Condition{
			Type:               ConditionReady,
			Status:             metav1.ConditionTrue,
			Reason:             ReasonReconciled,
			Message:            "Test",
			LastTransitionTime: metav1.Now(),
			ObservedGeneration: 1,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if copied == original {
			t.Error("DeepCopy returned same pointer")
		}

		var nilCondition *Condition
		if nilCondition.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("AppliedGateway", func(t *testing.T) {
		original := &AppliedGateway{
			Name:        "gateway",
			Namespace:   "default",
			LastApplied: metav1.Now(),
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGateway *AppliedGateway
		if nilGateway.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("Destination", func(t *testing.T) {
		original := &Destination{Host: "backend", Port: 8080}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilDest *Destination
		if nilDest.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RouteDestination", func(t *testing.T) {
		original := &RouteDestination{
			Destination: Destination{Host: "backend", Port: 8080},
			Weight:      100,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRD *RouteDestination
		if nilRD.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("StringMatch", func(t *testing.T) {
		original := &StringMatch{Exact: "value", Prefix: "pre", Regex: ".*"}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilSM *StringMatch
		if nilSM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("HeaderMatch", func(t *testing.T) {
		present := true
		original := &HeaderMatch{
			Name:    "X-Custom",
			Exact:   "value",
			Present: &present,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilHM *HeaderMatch
		if nilHM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("QueryParamMatch", func(t *testing.T) {
		present := true
		original := &QueryParamMatch{
			Name:    "version",
			Exact:   "v1",
			Present: &present,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilQPM *QueryParamMatch
		if nilQPM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RetryPolicy", func(t *testing.T) {
		original := &RetryPolicy{
			Attempts:      3,
			PerTryTimeout: Duration("10s"),
			RetryOn:       "5xx",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRP *RetryPolicy
		if nilRP.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCRetryPolicy", func(t *testing.T) {
		original := &GRPCRetryPolicy{
			Attempts:            3,
			PerTryTimeout:       Duration("10s"),
			RetryOn:             "unavailable",
			BackoffBaseInterval: Duration("100ms"),
			BackoffMaxInterval:  Duration("1s"),
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGRP *GRPCRetryPolicy
		if nilGRP.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("HeaderOperation", func(t *testing.T) {
		original := &HeaderOperation{
			Set:    map[string]string{"X-Gateway": "avapigw"},
			Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
			Remove: []string{"X-Internal"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}
		// Verify deep copy of maps and slices
		if &copied.Set == &original.Set {
			t.Error("Set map not deep copied")
		}

		var nilHO *HeaderOperation
		if nilHO.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("HeaderManipulation", func(t *testing.T) {
		original := &HeaderManipulation{
			Request:  &HeaderOperation{Set: map[string]string{"X-Gateway": "avapigw"}},
			Response: &HeaderOperation{Set: map[string]string{"X-Response": "value"}},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilHM *HeaderManipulation
		if nilHM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RateLimitConfig", func(t *testing.T) {
		original := &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
			PerClient:         true,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRLC *RateLimitConfig
		if nilRLC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("CircuitBreakerConfig", func(t *testing.T) {
		original := &CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        5,
			Timeout:          Duration("30s"),
			HalfOpenRequests: 3,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilCBC *CircuitBreakerConfig
		if nilCBC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("LoadBalancerConfig", func(t *testing.T) {
		original := &LoadBalancerConfig{Algorithm: LoadBalancerRoundRobin}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilLBC *LoadBalancerConfig
		if nilLBC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("MaxSessionsConfig", func(t *testing.T) {
		original := &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
			QueueSize:     100,
			QueueTimeout:  Duration("10s"),
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilMSC *MaxSessionsConfig
		if nilMSC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RequestLimitsConfig", func(t *testing.T) {
		original := &RequestLimitsConfig{
			MaxBodySize:   10485760,
			MaxHeaderSize: 1048576,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRLC *RequestLimitsConfig
		if nilRLC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("HealthCheckConfig", func(t *testing.T) {
		original := &HealthCheckConfig{
			Path:     "/health",
			Interval: Duration("10s"),
			Timeout:  Duration("5s"),
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilHCC *HealthCheckConfig
		if nilHCC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCHealthCheckConfig", func(t *testing.T) {
		original := &GRPCHealthCheckConfig{
			Service:  "grpc.health.v1.Health",
			Interval: Duration("10s"),
			Timeout:  Duration("5s"),
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGHCC *GRPCHealthCheckConfig
		if nilGHCC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCConnectionPoolConfig", func(t *testing.T) {
		original := &GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: 100,
			IdleConnTimeout: Duration("5m"),
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGCPC *GRPCConnectionPoolConfig
		if nilGCPC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendHost", func(t *testing.T) {
		original := &BackendHost{Address: "backend", Port: 8080, Weight: 100}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBH *BackendHost
		if nilBH.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("SecretKeySelector", func(t *testing.T) {
		original := &SecretKeySelector{Name: "secret", Key: "key"}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilSKS *SecretKeySelector
		if nilSKS.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestAuthTypes_DeepCopy tests DeepCopy for authentication/authorization types
func TestAuthTypes_DeepCopy(t *testing.T) {
	t.Run("AuthenticationConfig", func(t *testing.T) {
		original := &AuthenticationConfig{
			Enabled: true,
			JWT: &JWTAuthConfig{
				Enabled:  true,
				Audience: []string{"api"},
			},
			SkipPaths: []string{"/health"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilAC *AuthenticationConfig
		if nilAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("JWTAuthConfig", func(t *testing.T) {
		original := &JWTAuthConfig{
			Enabled:  true,
			Issuer:   "https://issuer.example.com",
			Audience: []string{"api", "web"},
			ClaimMapping: &ClaimMappingConfig{
				Roles: "roles",
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilJAC *JWTAuthConfig
		if nilJAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("ClaimMappingConfig", func(t *testing.T) {
		original := &ClaimMappingConfig{
			Roles:       "roles",
			Permissions: "permissions",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilCMC *ClaimMappingConfig
		if nilCMC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("APIKeyAuthConfig", func(t *testing.T) {
		original := &APIKeyAuthConfig{
			Enabled: true,
			Header:  "X-API-Key",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilAKAC *APIKeyAuthConfig
		if nilAKAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("MTLSAuthConfig", func(t *testing.T) {
		original := &MTLSAuthConfig{
			Enabled:    true,
			AllowedCNs: []string{"client1"},
			AllowedOUs: []string{"engineering"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilMAC *MTLSAuthConfig
		if nilMAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("OIDCAuthConfig", func(t *testing.T) {
		original := &OIDCAuthConfig{
			Enabled: true,
			Providers: []OIDCProviderConfig{
				{
					Name:   "keycloak",
					Scopes: []string{"openid"},
				},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilOAC *OIDCAuthConfig
		if nilOAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("OIDCProviderConfig", func(t *testing.T) {
		original := &OIDCProviderConfig{
			Name:            "keycloak",
			Scopes:          []string{"openid", "profile"},
			ClientSecretRef: &SecretKeySelector{Name: "secret", Key: "key"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilOPC *OIDCProviderConfig
		if nilOPC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("AuthorizationConfig", func(t *testing.T) {
		original := &AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			SkipPaths:     []string{"/public"},
			Cache: &AuthzCacheConfig{
				Enabled: true,
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilAC *AuthorizationConfig
		if nilAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RBACConfig", func(t *testing.T) {
		original := &RBACConfig{
			Enabled: true,
			Policies: []RBACPolicyConfig{
				{
					Name:      "admin",
					Roles:     []string{"admin"},
					Resources: []string{"*"},
					Actions:   []string{"*"},
				},
			},
			RoleHierarchy: map[string][]string{
				"admin": {"user"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRC *RBACConfig
		if nilRC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RBACPolicyConfig", func(t *testing.T) {
		original := &RBACPolicyConfig{
			Name:      "admin",
			Roles:     []string{"admin"},
			Resources: []string{"*"},
			Actions:   []string{"*"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRPC *RBACPolicyConfig
		if nilRPC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("ABACConfig", func(t *testing.T) {
		original := &ABACConfig{
			Enabled: true,
			Policies: []ABACPolicyConfig{
				{
					Name:       "owner",
					Expression: "request.user == resource.owner",
					Resources:  []string{"/api/*"},
					Actions:    []string{"GET"},
				},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilAC *ABACConfig
		if nilAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("ABACPolicyConfig", func(t *testing.T) {
		original := &ABACPolicyConfig{
			Name:       "owner",
			Expression: "request.user == resource.owner",
			Resources:  []string{"/api/*"},
			Actions:    []string{"GET"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilAPC *ABACPolicyConfig
		if nilAPC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("ExternalAuthzConfig", func(t *testing.T) {
		original := &ExternalAuthzConfig{
			Enabled: true,
			OPA: &OPAAuthzConfig{
				URL:     "http://opa:8181",
				Headers: map[string]string{"X-Custom": "value"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilEAC *ExternalAuthzConfig
		if nilEAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("OPAAuthzConfig", func(t *testing.T) {
		original := &OPAAuthzConfig{
			URL:     "http://opa:8181",
			Policy:  "authz/allow",
			Headers: map[string]string{"X-Custom": "value"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilOAC *OPAAuthzConfig
		if nilOAC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("AuthzCacheConfig", func(t *testing.T) {
		original := &AuthzCacheConfig{
			Enabled: true,
			TTL:     Duration("5m"),
			MaxSize: 1000,
			Type:    "memory",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilACC *AuthzCacheConfig
		if nilACC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestTransformTypes_DeepCopy tests DeepCopy for transform types
func TestTransformTypes_DeepCopy(t *testing.T) {
	t.Run("TransformConfig", func(t *testing.T) {
		original := &TransformConfig{
			Request: &RequestTransform{
				Template: `{"wrapped": {{.Body}}}`,
			},
			Response: &ResponseTransform{
				AllowFields:   []string{"id"},
				DenyFields:    []string{"password"},
				FieldMappings: map[string]string{"created_at": "createdAt"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilTC *TransformConfig
		if nilTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RequestTransform", func(t *testing.T) {
		original := &RequestTransform{Template: `{"wrapped": {{.Body}}}`}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRT *RequestTransform
		if nilRT.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("ResponseTransform", func(t *testing.T) {
		original := &ResponseTransform{
			AllowFields:   []string{"id", "name"},
			DenyFields:    []string{"password"},
			FieldMappings: map[string]string{"created_at": "createdAt"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRT *ResponseTransform
		if nilRT.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendTransformConfig", func(t *testing.T) {
		original := &BackendTransformConfig{
			Request: &BackendRequestTransform{
				Template: `{"wrapped": {{.Body}}}`,
				Headers: &HeaderOperation{
					Set: map[string]string{"X-Gateway": "avapigw"},
				},
			},
			Response: &BackendResponseTransform{
				AllowFields:   []string{"id"},
				FieldMappings: map[string]string{"created_at": "createdAt"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBTC *BackendTransformConfig
		if nilBTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendRequestTransform", func(t *testing.T) {
		original := &BackendRequestTransform{
			Template: `{"wrapped": {{.Body}}}`,
			Headers: &HeaderOperation{
				Set: map[string]string{"X-Gateway": "avapigw"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBRT *BackendRequestTransform
		if nilBRT.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendResponseTransform", func(t *testing.T) {
		original := &BackendResponseTransform{
			AllowFields:   []string{"id"},
			DenyFields:    []string{"password"},
			FieldMappings: map[string]string{"created_at": "createdAt"},
			Headers: &HeaderOperation{
				Set: map[string]string{"X-Response": "value"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBRT *BackendResponseTransform
		if nilBRT.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCTransformConfig", func(t *testing.T) {
		original := &GRPCTransformConfig{
			FieldMask: &FieldMaskConfig{
				Paths: []string{"user.id", "user.name"},
			},
			Metadata: &MetadataManipulation{
				Static:  map[string]string{"x-source": "gateway"},
				Dynamic: map[string]string{"x-request-id": "{{.RequestID}}"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGTC *GRPCTransformConfig
		if nilGTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("FieldMaskConfig", func(t *testing.T) {
		original := &FieldMaskConfig{Paths: []string{"user.id", "user.name"}}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilFMC *FieldMaskConfig
		if nilFMC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("MetadataManipulation", func(t *testing.T) {
		original := &MetadataManipulation{
			Static:  map[string]string{"x-source": "gateway"},
			Dynamic: map[string]string{"x-request-id": "{{.RequestID}}"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilMM *MetadataManipulation
		if nilMM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCBackendTransformConfig", func(t *testing.T) {
		original := &GRPCBackendTransformConfig{
			FieldMask: &GRPCFieldMaskConfig{
				Paths: []string{"user.id"},
			},
			Metadata: &GRPCMetadataManipulation{
				Static:  map[string]string{"x-source": "gateway"},
				Dynamic: map[string]string{"x-request-id": "{{.RequestID}}"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGBTC *GRPCBackendTransformConfig
		if nilGBTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCFieldMaskConfig", func(t *testing.T) {
		original := &GRPCFieldMaskConfig{Paths: []string{"user.id"}}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGFMC *GRPCFieldMaskConfig
		if nilGFMC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCMetadataManipulation", func(t *testing.T) {
		original := &GRPCMetadataManipulation{
			Static:  map[string]string{"x-source": "gateway"},
			Dynamic: map[string]string{"x-request-id": "{{.RequestID}}"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGMM *GRPCMetadataManipulation
		if nilGMM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestCacheEncodingTypes_DeepCopy tests DeepCopy for cache and encoding types
func TestCacheEncodingTypes_DeepCopy(t *testing.T) {
	t.Run("CacheConfig", func(t *testing.T) {
		original := &CacheConfig{
			Enabled:       true,
			TTL:           Duration("5m"),
			KeyComponents: []string{"path", "query"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilCC *CacheConfig
		if nilCC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendCacheConfig", func(t *testing.T) {
		original := &BackendCacheConfig{
			Enabled:       true,
			TTL:           Duration("10m"),
			KeyComponents: []string{"path", "query"},
			Type:          "redis",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBCC *BackendCacheConfig
		if nilBCC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("EncodingConfig", func(t *testing.T) {
		original := &EncodingConfig{
			Request:  &EncodingSettings{ContentType: "application/json"},
			Response: &EncodingSettings{ContentType: "application/json"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilEC *EncodingConfig
		if nilEC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("EncodingSettings", func(t *testing.T) {
		original := &EncodingSettings{ContentType: "application/json"}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilES *EncodingSettings
		if nilES.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendEncodingConfig", func(t *testing.T) {
		original := &BackendEncodingConfig{
			Request:  &BackendEncodingSettings{ContentType: "application/json", Compression: "gzip"},
			Response: &BackendEncodingSettings{ContentType: "application/json", Compression: "br"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBEC *BackendEncodingConfig
		if nilBEC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendEncodingSettings", func(t *testing.T) {
		original := &BackendEncodingSettings{ContentType: "application/json", Compression: "gzip"}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBES *BackendEncodingSettings
		if nilBES.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestTLSTypes_DeepCopy tests DeepCopy for TLS types
func TestTLSTypes_DeepCopy(t *testing.T) {
	t.Run("RouteTLSConfig", func(t *testing.T) {
		original := &RouteTLSConfig{
			CertFile:     "/certs/tls.crt",
			KeyFile:      "/certs/tls.key",
			SNIHosts:     []string{"api.example.com"},
			CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			ClientValidation: &ClientValidationConfig{
				Enabled:    true,
				AllowedCNs: []string{"client1"},
			},
			Vault: &VaultTLSConfig{
				Enabled:  true,
				AltNames: []string{"api2.example.com"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRTC *RouteTLSConfig
		if nilRTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("BackendTLSConfig", func(t *testing.T) {
		original := &BackendTLSConfig{
			Enabled:      true,
			CertFile:     "/certs/tls.crt",
			CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			ALPN:         []string{"h2"},
			Vault: &VaultBackendTLSConfig{
				Enabled:  true,
				AltNames: []string{"backend2.example.com"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilBTC *BackendTLSConfig
		if nilBTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("ClientValidationConfig", func(t *testing.T) {
		original := &ClientValidationConfig{
			Enabled:     true,
			AllowedCNs:  []string{"client1"},
			AllowedSANs: []string{"san1.example.com"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilCVC *ClientValidationConfig
		if nilCVC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("VaultTLSConfig", func(t *testing.T) {
		original := &VaultTLSConfig{
			Enabled:  true,
			PKIMount: "pki",
			Role:     "api-route",
			AltNames: []string{"api2.example.com"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilVTC *VaultTLSConfig
		if nilVTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("VaultBackendTLSConfig", func(t *testing.T) {
		original := &VaultBackendTLSConfig{
			Enabled:  true,
			PKIMount: "pki",
			Role:     "backend",
			AltNames: []string{"backend2.example.com"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilVBTC *VaultBackendTLSConfig
		if nilVBTC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestRouteMatchTypes_DeepCopy tests DeepCopy for route match types
func TestRouteMatchTypes_DeepCopy(t *testing.T) {
	t.Run("RouteMatch", func(t *testing.T) {
		present := true
		original := &RouteMatch{
			URI: &URIMatch{
				Prefix: "/api/v1",
			},
			Methods: []string{"GET", "POST"},
			Headers: []HeaderMatch{
				{Name: "X-Custom", Exact: "value", Present: &present},
			},
			QueryParams: []QueryParamMatch{
				{Name: "version", Exact: "v1"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRM *RouteMatch
		if nilRM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("URIMatch", func(t *testing.T) {
		original := &URIMatch{Exact: "/api/v1/users", Prefix: "/api", Regex: ".*"}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilUM *URIMatch
		if nilUM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("GRPCRouteMatch", func(t *testing.T) {
		original := &GRPCRouteMatch{
			Service: &StringMatch{Exact: "myservice.v1.MyService"},
			Method:  &StringMatch{Exact: "GetUser"},
			Metadata: []MetadataMatch{
				{Name: "x-custom", Exact: "value"},
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilGRM *GRPCRouteMatch
		if nilGRM.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestMiscTypes_DeepCopy tests DeepCopy for miscellaneous types
func TestMiscTypes_DeepCopy(t *testing.T) {
	t.Run("RedirectConfig", func(t *testing.T) {
		original := &RedirectConfig{
			URI:        "/new-path",
			Code:       301,
			Scheme:     "https",
			Host:       "example.com",
			Port:       443,
			StripQuery: true,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRC *RedirectConfig
		if nilRC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("RewriteConfig", func(t *testing.T) {
		original := &RewriteConfig{URI: "/internal", Authority: "internal.example.com"}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilRC *RewriteConfig
		if nilRC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("DirectResponseConfig", func(t *testing.T) {
		original := &DirectResponseConfig{
			Status:  200,
			Body:    `{"status":"ok"}`,
			Headers: map[string]string{"Content-Type": "application/json"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilDRC *DirectResponseConfig
		if nilDRC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("MirrorConfig", func(t *testing.T) {
		original := &MirrorConfig{
			Destination: Destination{Host: "mirror", Port: 8080},
			Percentage:  10,
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilMC *MirrorConfig
		if nilMC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("FaultInjection", func(t *testing.T) {
		original := &FaultInjection{
			Delay: &FaultDelay{FixedDelay: Duration("100ms"), Percentage: 10},
			Abort: &FaultAbort{HTTPStatus: 503, Percentage: 5},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilFI *FaultInjection
		if nilFI.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("FaultDelay", func(t *testing.T) {
		original := &FaultDelay{FixedDelay: Duration("100ms"), Percentage: 10}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilFD *FaultDelay
		if nilFD.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("FaultAbort", func(t *testing.T) {
		original := &FaultAbort{HTTPStatus: 503, Percentage: 5}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilFA *FaultAbort
		if nilFA.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("CORSConfig", func(t *testing.T) {
		original := &CORSConfig{
			AllowOrigins:  []string{"https://example.com"},
			AllowMethods:  []string{"GET", "POST"},
			AllowHeaders:  []string{"Content-Type"},
			ExposeHeaders: []string{"X-Request-ID"},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilCC *CORSConfig
		if nilCC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("SecurityConfig", func(t *testing.T) {
		original := &SecurityConfig{
			Enabled: true,
			Headers: &SecurityHeadersConfig{
				Enabled:       true,
				XFrameOptions: "DENY",
			},
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilSC *SecurityConfig
		if nilSC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("SecurityHeadersConfig", func(t *testing.T) {
		original := &SecurityHeadersConfig{
			Enabled:       true,
			XFrameOptions: "DENY",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}

		var nilSHC *SecurityHeadersConfig
		if nilSHC.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})
}

// TestRedisSentinelSpec_DeepCopy tests the DeepCopy methods for RedisSentinelSpec
func TestRedisSentinelSpec_DeepCopy(t *testing.T) {
	t.Run("full config", func(t *testing.T) {
		original := &RedisSentinelSpec{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"sentinel-0:26379", "sentinel-1:26379", "sentinel-2:26379"},
			SentinelPassword: "sentinelpass",
			Password:         "masterpass",
			DB:               5,
		}

		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if copied == original {
			t.Error("DeepCopy returned same pointer")
		}

		// Verify values are equal
		if !reflect.DeepEqual(original, copied) {
			t.Error("DeepCopy did not create an equal object")
		}

		// Verify slice independence
		copied.SentinelAddrs[0] = "modified:26379"
		if original.SentinelAddrs[0] == "modified:26379" {
			t.Error("Modifying copy's SentinelAddrs affected original")
		}

		// Verify scalar independence
		copied.MasterName = "modified"
		if original.MasterName == "modified" {
			t.Error("Modifying copy's MasterName affected original")
		}

		copied.DB = 10
		if original.DB == 10 {
			t.Error("Modifying copy's DB affected original")
		}
	})

	t.Run("nil copy", func(t *testing.T) {
		var nilSpec *RedisSentinelSpec
		if nilSpec.DeepCopy() != nil {
			t.Error("DeepCopy of nil should return nil")
		}
	})

	t.Run("empty addrs", func(t *testing.T) {
		original := &RedisSentinelSpec{
			MasterName: "mymaster",
		}
		copied := original.DeepCopy()
		if copied == nil {
			t.Fatal("DeepCopy returned nil")
		}
		if copied.SentinelAddrs != nil {
			t.Error("Expected nil SentinelAddrs for empty original")
		}
	})

	t.Run("DeepCopyInto", func(t *testing.T) {
		original := &RedisSentinelSpec{
			MasterName:    "mymaster",
			SentinelAddrs: []string{"sentinel-0:26379"},
			DB:            3,
		}
		out := &RedisSentinelSpec{}
		original.DeepCopyInto(out)

		if !reflect.DeepEqual(original, out) {
			t.Error("DeepCopyInto did not create an equal object")
		}

		// Verify independence
		out.SentinelAddrs[0] = "modified"
		if original.SentinelAddrs[0] == "modified" {
			t.Error("Modifying DeepCopyInto target affected original")
		}
	})
}

// TestBackendCacheConfig_DeepCopy_WithSentinel tests DeepCopy for BackendCacheConfig with Sentinel
func TestBackendCacheConfig_DeepCopy_WithSentinel(t *testing.T) {
	original := &BackendCacheConfig{
		Enabled:              true,
		TTL:                  Duration("10m"),
		KeyComponents:        []string{"path", "query"},
		StaleWhileRevalidate: Duration("2m"),
		Type:                 "redis",
		Sentinel: &RedisSentinelSpec{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"sentinel-0:26379", "sentinel-1:26379"},
			SentinelPassword: "sentinelpass",
			Password:         "masterpass",
			DB:               3,
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	// Verify equality
	if !reflect.DeepEqual(original, copied) {
		t.Error("DeepCopy did not create an equal object")
	}

	// Verify sentinel pointer independence
	if copied.Sentinel == original.Sentinel {
		t.Error("Sentinel pointer not deep copied")
	}

	// Verify sentinel slice independence
	copied.Sentinel.SentinelAddrs[0] = "modified:26379"
	if original.Sentinel.SentinelAddrs[0] == "modified:26379" {
		t.Error("Modifying copy's Sentinel.SentinelAddrs affected original")
	}

	// Verify KeyComponents independence
	copied.KeyComponents[0] = "modified"
	if original.KeyComponents[0] == "modified" {
		t.Error("Modifying copy's KeyComponents affected original")
	}

	// Verify sentinel scalar independence
	copied.Sentinel.MasterName = "modified"
	if original.Sentinel.MasterName == "modified" {
		t.Error("Modifying copy's Sentinel.MasterName affected original")
	}
}

// TestAuthzCacheConfig_DeepCopy_WithSentinel tests DeepCopy for AuthzCacheConfig with Sentinel
func TestAuthzCacheConfig_DeepCopy_WithSentinel(t *testing.T) {
	original := &AuthzCacheConfig{
		Enabled: true,
		TTL:     Duration("5m"),
		MaxSize: 1000,
		Type:    "redis",
		Sentinel: &RedisSentinelSpec{
			MasterName:       "mymaster",
			SentinelAddrs:    []string{"sentinel-0:26379", "sentinel-1:26379", "sentinel-2:26379"},
			SentinelPassword: "sentinelpass",
			Password:         "masterpass",
			DB:               7,
		},
	}

	copied := original.DeepCopy()
	if copied == nil {
		t.Fatal("DeepCopy returned nil")
	}

	// Verify equality
	if !reflect.DeepEqual(original, copied) {
		t.Error("DeepCopy did not create an equal object")
	}

	// Verify sentinel pointer independence
	if copied.Sentinel == original.Sentinel {
		t.Error("Sentinel pointer not deep copied")
	}

	// Verify sentinel slice independence
	copied.Sentinel.SentinelAddrs[1] = "modified:26379"
	if original.Sentinel.SentinelAddrs[1] == "modified:26379" {
		t.Error("Modifying copy's Sentinel.SentinelAddrs affected original")
	}

	// Verify sentinel scalar independence
	copied.Sentinel.DB = 0
	if original.Sentinel.DB == 0 {
		t.Error("Modifying copy's Sentinel.DB affected original")
	}

	// Test with nil sentinel
	originalNoSentinel := &AuthzCacheConfig{
		Enabled: true,
		TTL:     Duration("5m"),
		Type:    "memory",
	}
	copiedNoSentinel := originalNoSentinel.DeepCopy()
	if copiedNoSentinel.Sentinel != nil {
		t.Error("Expected nil Sentinel when original has nil Sentinel")
	}
}

// TestDeepCopyInto_Isolation verifies that DeepCopyInto creates independent copies
func TestDeepCopyInto_Isolation(t *testing.T) {
	original := &APIRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name: "original",
		},
		Spec: APIRouteSpec{
			Match: []RouteMatch{
				{
					Methods: []string{"GET"},
				},
			},
			CORS: &CORSConfig{
				AllowOrigins: []string{"https://example.com"},
			},
		},
	}

	copied := &APIRoute{}
	original.DeepCopyInto(copied)

	// Modify the copy
	copied.Name = "modified"
	copied.Spec.Match[0].Methods[0] = "POST"
	copied.Spec.CORS.AllowOrigins[0] = "https://modified.com"

	// Verify original is unchanged
	if original.Name != "original" {
		t.Error("Original name was modified")
	}
	if original.Spec.Match[0].Methods[0] != "GET" {
		t.Error("Original methods were modified")
	}
	if original.Spec.CORS.AllowOrigins[0] != "https://example.com" {
		t.Error("Original CORS origins were modified")
	}
}

// TestDeepCopy_MapIsolation verifies that maps are deeply copied
func TestDeepCopy_MapIsolation(t *testing.T) {
	original := &HeaderOperation{
		Set:    map[string]string{"key1": "value1"},
		Add:    map[string]string{"key2": "value2"},
		Remove: []string{"key3"},
	}

	copied := original.DeepCopy()

	// Modify the copy
	copied.Set["key1"] = "modified"
	copied.Add["key2"] = "modified"
	copied.Remove[0] = "modified"

	// Verify original is unchanged
	if original.Set["key1"] != "value1" {
		t.Error("Original Set map was modified")
	}
	if original.Add["key2"] != "value2" {
		t.Error("Original Add map was modified")
	}
	if original.Remove[0] != "key3" {
		t.Error("Original Remove slice was modified")
	}
}

// TestDeepCopy_NestedStructIsolation verifies that nested structs are deeply copied
func TestDeepCopy_NestedStructIsolation(t *testing.T) {
	original := &AuthenticationConfig{
		Enabled: true,
		JWT: &JWTAuthConfig{
			Enabled:  true,
			Audience: []string{"api"},
			ClaimMapping: &ClaimMappingConfig{
				Roles: "roles",
			},
		},
	}

	copied := original.DeepCopy()

	// Modify the copy
	copied.JWT.Audience[0] = "modified"
	copied.JWT.ClaimMapping.Roles = "modified"

	// Verify original is unchanged
	if original.JWT.Audience[0] != "api" {
		t.Error("Original JWT audience was modified")
	}
	if original.JWT.ClaimMapping.Roles != "roles" {
		t.Error("Original ClaimMapping roles was modified")
	}
}

// TestDeepCopy_Equality verifies that DeepCopy creates equal objects
func TestDeepCopy_Equality(t *testing.T) {
	original := &RBACConfig{
		Enabled: true,
		Policies: []RBACPolicyConfig{
			{
				Name:      "admin",
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
	}

	copied := original.DeepCopy()

	// Verify equality using reflect.DeepEqual
	if !reflect.DeepEqual(original, copied) {
		t.Error("DeepCopy did not create an equal object")
	}
}

// Helper function to create a pointer to metav1.Time
func ptrTime(t metav1.Time) *metav1.Time {
	return &t
}

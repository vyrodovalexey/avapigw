// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDuration_String(t *testing.T) {
	tests := []struct {
		name     string
		duration Duration
		want     string
	}{
		{
			name:     "empty duration",
			duration: Duration(""),
			want:     "",
		},
		{
			name:     "seconds",
			duration: Duration("30s"),
			want:     "30s",
		},
		{
			name:     "minutes",
			duration: Duration("5m"),
			want:     "5m",
		},
		{
			name:     "hours",
			duration: Duration("1h"),
			want:     "1h",
		},
		{
			name:     "complex duration",
			duration: Duration("1h30m45s"),
			want:     "1h30m45s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.duration); got != tt.want {
				t.Errorf("Duration = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConditionType_Constants(t *testing.T) {
	tests := []struct {
		name     string
		condType ConditionType
		want     string
	}{
		{
			name:     "ConditionReady",
			condType: ConditionReady,
			want:     "Ready",
		},
		{
			name:     "ConditionValid",
			condType: ConditionValid,
			want:     "Valid",
		},
		{
			name:     "ConditionHealthy",
			condType: ConditionHealthy,
			want:     "Healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.condType); got != tt.want {
				t.Errorf("ConditionType = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConditionReason_Constants(t *testing.T) {
	tests := []struct {
		name   string
		reason ConditionReason
		want   string
	}{
		{
			name:   "ReasonReconciled",
			reason: ReasonReconciled,
			want:   "Reconciled",
		},
		{
			name:   "ReasonReconcileFailed",
			reason: ReasonReconcileFailed,
			want:   "ReconcileFailed",
		},
		{
			name:   "ReasonValidationPassed",
			reason: ReasonValidationPassed,
			want:   "ValidationPassed",
		},
		{
			name:   "ReasonValidationFailed",
			reason: ReasonValidationFailed,
			want:   "ValidationFailed",
		},
		{
			name:   "ReasonHealthCheckOK",
			reason: ReasonHealthCheckOK,
			want:   "HealthCheckOK",
		},
		{
			name:   "ReasonHealthCheckFail",
			reason: ReasonHealthCheckFail,
			want:   "HealthCheckFailed",
		},
		{
			name:   "ReasonApplied",
			reason: ReasonApplied,
			want:   "Applied",
		},
		{
			name:   "ReasonApplyFailed",
			reason: ReasonApplyFailed,
			want:   "ApplyFailed",
		},
		{
			name:   "ReasonDeleted",
			reason: ReasonDeleted,
			want:   "Deleted",
		},
		{
			name:   "ReasonDeleteFailed",
			reason: ReasonDeleteFailed,
			want:   "DeleteFailed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.reason); got != tt.want {
				t.Errorf("ConditionReason = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCondition_Fields(t *testing.T) {
	now := metav1.Now()
	condition := Condition{
		Type:               ConditionReady,
		Status:             metav1.ConditionTrue,
		Reason:             ReasonReconciled,
		Message:            "Test message",
		LastTransitionTime: now,
		ObservedGeneration: 1,
	}

	if condition.Type != ConditionReady {
		t.Errorf("Type = %v, want %v", condition.Type, ConditionReady)
	}
	if condition.Status != metav1.ConditionTrue {
		t.Errorf("Status = %v, want %v", condition.Status, metav1.ConditionTrue)
	}
	if condition.Reason != ReasonReconciled {
		t.Errorf("Reason = %v, want %v", condition.Reason, ReasonReconciled)
	}
	if condition.Message != "Test message" {
		t.Errorf("Message = %v, want %v", condition.Message, "Test message")
	}
	if condition.ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %v, want %v", condition.ObservedGeneration, 1)
	}
}

func TestAppliedGateway_Fields(t *testing.T) {
	now := metav1.Now()
	gateway := AppliedGateway{
		Name:        "test-gateway",
		Namespace:   "test-namespace",
		LastApplied: now,
	}

	if gateway.Name != "test-gateway" {
		t.Errorf("Name = %v, want %v", gateway.Name, "test-gateway")
	}
	if gateway.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want %v", gateway.Namespace, "test-namespace")
	}
}

func TestStringMatch_Fields(t *testing.T) {
	tests := []struct {
		name  string
		match StringMatch
	}{
		{
			name: "exact match",
			match: StringMatch{
				Exact: "exact-value",
			},
		},
		{
			name: "prefix match",
			match: StringMatch{
				Prefix: "prefix-",
			},
		},
		{
			name: "regex match",
			match: StringMatch{
				Regex: "^test.*$",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the match is properly set
			if tt.match.Exact != "" && tt.match.Exact != "exact-value" {
				t.Errorf("Exact = %v, want exact-value", tt.match.Exact)
			}
			if tt.match.Prefix != "" && tt.match.Prefix != "prefix-" {
				t.Errorf("Prefix = %v, want prefix-", tt.match.Prefix)
			}
			if tt.match.Regex != "" && tt.match.Regex != "^test.*$" {
				t.Errorf("Regex = %v, want ^test.*$", tt.match.Regex)
			}
		})
	}
}

func TestHeaderMatch_Fields(t *testing.T) {
	present := true
	absent := false
	match := HeaderMatch{
		Name:    "X-Custom-Header",
		Exact:   "exact-value",
		Prefix:  "prefix-",
		Regex:   "^test.*$",
		Present: &present,
		Absent:  &absent,
	}

	if match.Name != "X-Custom-Header" {
		t.Errorf("Name = %v, want X-Custom-Header", match.Name)
	}
	if match.Exact != "exact-value" {
		t.Errorf("Exact = %v, want exact-value", match.Exact)
	}
	if match.Prefix != "prefix-" {
		t.Errorf("Prefix = %v, want prefix-", match.Prefix)
	}
	if match.Regex != "^test.*$" {
		t.Errorf("Regex = %v, want ^test.*$", match.Regex)
	}
	if match.Present == nil || !*match.Present {
		t.Error("Present should be true")
	}
	if match.Absent == nil || *match.Absent {
		t.Error("Absent should be false")
	}
}

func TestDestination_Fields(t *testing.T) {
	dest := Destination{
		Host: "backend-service",
		Port: 8080,
	}

	if dest.Host != "backend-service" {
		t.Errorf("Host = %v, want backend-service", dest.Host)
	}
	if dest.Port != 8080 {
		t.Errorf("Port = %v, want 8080", dest.Port)
	}
}

func TestRouteDestination_Fields(t *testing.T) {
	rd := RouteDestination{
		Destination: Destination{
			Host: "backend-service",
			Port: 8080,
		},
		Weight: 100,
	}

	if rd.Destination.Host != "backend-service" {
		t.Errorf("Destination.Host = %v, want backend-service", rd.Destination.Host)
	}
	if rd.Destination.Port != 8080 {
		t.Errorf("Destination.Port = %v, want 8080", rd.Destination.Port)
	}
	if rd.Weight != 100 {
		t.Errorf("Weight = %v, want 100", rd.Weight)
	}
}

func TestRetryPolicy_Fields(t *testing.T) {
	policy := RetryPolicy{
		Attempts:      3,
		PerTryTimeout: Duration("10s"),
		RetryOn:       "5xx,reset,connect-failure",
	}

	if policy.Attempts != 3 {
		t.Errorf("Attempts = %v, want 3", policy.Attempts)
	}
	if policy.PerTryTimeout != Duration("10s") {
		t.Errorf("PerTryTimeout = %v, want 10s", policy.PerTryTimeout)
	}
	if policy.RetryOn != "5xx,reset,connect-failure" {
		t.Errorf("RetryOn = %v, want 5xx,reset,connect-failure", policy.RetryOn)
	}
}

func TestGRPCRetryPolicy_Fields(t *testing.T) {
	policy := GRPCRetryPolicy{
		Attempts:            3,
		PerTryTimeout:       Duration("10s"),
		RetryOn:             "unavailable,resource-exhausted",
		BackoffBaseInterval: Duration("100ms"),
		BackoffMaxInterval:  Duration("1s"),
	}

	if policy.Attempts != 3 {
		t.Errorf("Attempts = %v, want 3", policy.Attempts)
	}
	if policy.PerTryTimeout != Duration("10s") {
		t.Errorf("PerTryTimeout = %v, want 10s", policy.PerTryTimeout)
	}
	if policy.RetryOn != "unavailable,resource-exhausted" {
		t.Errorf("RetryOn = %v, want unavailable,resource-exhausted", policy.RetryOn)
	}
	if policy.BackoffBaseInterval != Duration("100ms") {
		t.Errorf("BackoffBaseInterval = %v, want 100ms", policy.BackoffBaseInterval)
	}
	if policy.BackoffMaxInterval != Duration("1s") {
		t.Errorf("BackoffMaxInterval = %v, want 1s", policy.BackoffMaxInterval)
	}
}

func TestHeaderOperation_Fields(t *testing.T) {
	op := HeaderOperation{
		Set:    map[string]string{"X-Gateway": "avapigw"},
		Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
		Remove: []string{"X-Internal-Header"},
	}

	if op.Set["X-Gateway"] != "avapigw" {
		t.Errorf("Set[X-Gateway] = %v, want avapigw", op.Set["X-Gateway"])
	}
	if op.Add["X-Request-ID"] != "{{.RequestID}}" {
		t.Errorf("Add[X-Request-ID] = %v, want {{.RequestID}}", op.Add["X-Request-ID"])
	}
	if len(op.Remove) != 1 || op.Remove[0] != "X-Internal-Header" {
		t.Errorf("Remove = %v, want [X-Internal-Header]", op.Remove)
	}
}

func TestHeaderManipulation_Fields(t *testing.T) {
	hm := HeaderManipulation{
		Request: &HeaderOperation{
			Set: map[string]string{"X-Gateway": "avapigw"},
		},
		Response: &HeaderOperation{
			Set: map[string]string{"X-Response-Time": "{{.ResponseTime}}"},
		},
	}

	if hm.Request == nil {
		t.Error("Request should not be nil")
	}
	if hm.Response == nil {
		t.Error("Response should not be nil")
	}
	if hm.Request.Set["X-Gateway"] != "avapigw" {
		t.Errorf("Request.Set[X-Gateway] = %v, want avapigw", hm.Request.Set["X-Gateway"])
	}
}

func TestRateLimitConfig_Fields(t *testing.T) {
	rl := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             200,
		PerClient:         true,
	}

	if !rl.Enabled {
		t.Error("Enabled should be true")
	}
	if rl.RequestsPerSecond != 100 {
		t.Errorf("RequestsPerSecond = %v, want 100", rl.RequestsPerSecond)
	}
	if rl.Burst != 200 {
		t.Errorf("Burst = %v, want 200", rl.Burst)
	}
	if !rl.PerClient {
		t.Error("PerClient should be true")
	}
}

func TestCORSConfig_Fields(t *testing.T) {
	cors := CORSConfig{
		AllowOrigins:     []string{"https://example.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"X-Request-ID"},
		MaxAge:           86400,
		AllowCredentials: true,
	}

	if len(cors.AllowOrigins) != 1 || cors.AllowOrigins[0] != "https://example.com" {
		t.Errorf("AllowOrigins = %v, want [https://example.com]", cors.AllowOrigins)
	}
	if len(cors.AllowMethods) != 2 {
		t.Errorf("AllowMethods = %v, want [GET POST]", cors.AllowMethods)
	}
	if cors.MaxAge != 86400 {
		t.Errorf("MaxAge = %v, want 86400", cors.MaxAge)
	}
	if !cors.AllowCredentials {
		t.Error("AllowCredentials should be true")
	}
}

func TestSecurityHeadersConfig_Fields(t *testing.T) {
	sh := SecurityHeadersConfig{
		Enabled:                 true,
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		XXSSProtection:          "1; mode=block",
		ContentSecurityPolicy:   "default-src 'self'",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
	}

	if !sh.Enabled {
		t.Error("Enabled should be true")
	}
	if sh.XFrameOptions != "DENY" {
		t.Errorf("XFrameOptions = %v, want DENY", sh.XFrameOptions)
	}
	if sh.XContentTypeOptions != "nosniff" {
		t.Errorf("XContentTypeOptions = %v, want nosniff", sh.XContentTypeOptions)
	}
}

func TestSecurityConfig_Fields(t *testing.T) {
	sc := SecurityConfig{
		Enabled: true,
		Headers: &SecurityHeadersConfig{
			Enabled:       true,
			XFrameOptions: "DENY",
		},
	}

	if !sc.Enabled {
		t.Error("Enabled should be true")
	}
	if sc.Headers == nil {
		t.Error("Headers should not be nil")
	}
}

func TestMaxSessionsConfig_Fields(t *testing.T) {
	ms := MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 1000,
		QueueSize:     100,
		QueueTimeout:  Duration("10s"),
	}

	if !ms.Enabled {
		t.Error("Enabled should be true")
	}
	if ms.MaxConcurrent != 1000 {
		t.Errorf("MaxConcurrent = %v, want 1000", ms.MaxConcurrent)
	}
	if ms.QueueSize != 100 {
		t.Errorf("QueueSize = %v, want 100", ms.QueueSize)
	}
	if ms.QueueTimeout != Duration("10s") {
		t.Errorf("QueueTimeout = %v, want 10s", ms.QueueTimeout)
	}
}

func TestRequestLimitsConfig_Fields(t *testing.T) {
	rl := RequestLimitsConfig{
		MaxBodySize:   10485760,
		MaxHeaderSize: 1048576,
	}

	if rl.MaxBodySize != 10485760 {
		t.Errorf("MaxBodySize = %v, want 10485760", rl.MaxBodySize)
	}
	if rl.MaxHeaderSize != 1048576 {
		t.Errorf("MaxHeaderSize = %v, want 1048576", rl.MaxHeaderSize)
	}
}

func TestVaultTLSConfig_Fields(t *testing.T) {
	vtls := VaultTLSConfig{
		Enabled:    true,
		PKIMount:   "pki",
		Role:       "api-route",
		CommonName: "api.example.com",
		AltNames:   []string{"api2.example.com"},
		TTL:        "24h",
	}

	if !vtls.Enabled {
		t.Error("Enabled should be true")
	}
	if vtls.PKIMount != "pki" {
		t.Errorf("PKIMount = %v, want pki", vtls.PKIMount)
	}
	if vtls.Role != "api-route" {
		t.Errorf("Role = %v, want api-route", vtls.Role)
	}
	if vtls.CommonName != "api.example.com" {
		t.Errorf("CommonName = %v, want api.example.com", vtls.CommonName)
	}
	if vtls.TTL != "24h" {
		t.Errorf("TTL = %v, want 24h", vtls.TTL)
	}
}

func TestClientValidationConfig_Fields(t *testing.T) {
	cv := ClientValidationConfig{
		Enabled:           true,
		CAFile:            "/certs/ca.crt",
		RequireClientCert: true,
		AllowedCNs:        []string{"client1", "client2"},
		AllowedSANs:       []string{"san1.example.com"},
	}

	if !cv.Enabled {
		t.Error("Enabled should be true")
	}
	if cv.CAFile != "/certs/ca.crt" {
		t.Errorf("CAFile = %v, want /certs/ca.crt", cv.CAFile)
	}
	if !cv.RequireClientCert {
		t.Error("RequireClientCert should be true")
	}
	if len(cv.AllowedCNs) != 2 {
		t.Errorf("AllowedCNs = %v, want [client1 client2]", cv.AllowedCNs)
	}
}

func TestRouteTLSConfig_Fields(t *testing.T) {
	rtls := RouteTLSConfig{
		CertFile:     "/certs/tls.crt",
		KeyFile:      "/certs/tls.key",
		SNIHosts:     []string{"api.example.com"},
		MinVersion:   "TLS12",
		MaxVersion:   "TLS13",
		CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		ClientValidation: &ClientValidationConfig{
			Enabled: true,
		},
		Vault: &VaultTLSConfig{
			Enabled: true,
		},
	}

	if rtls.CertFile != "/certs/tls.crt" {
		t.Errorf("CertFile = %v, want /certs/tls.crt", rtls.CertFile)
	}
	if rtls.KeyFile != "/certs/tls.key" {
		t.Errorf("KeyFile = %v, want /certs/tls.key", rtls.KeyFile)
	}
	if rtls.MinVersion != "TLS12" {
		t.Errorf("MinVersion = %v, want TLS12", rtls.MinVersion)
	}
	if rtls.MaxVersion != "TLS13" {
		t.Errorf("MaxVersion = %v, want TLS13", rtls.MaxVersion)
	}
	if rtls.ClientValidation == nil {
		t.Error("ClientValidation should not be nil")
	}
	if rtls.Vault == nil {
		t.Error("Vault should not be nil")
	}
}

func TestMirrorConfig_Fields(t *testing.T) {
	mc := MirrorConfig{
		Destination: Destination{
			Host: "mirror-service",
			Port: 8080,
		},
		Percentage: 10,
	}

	if mc.Destination.Host != "mirror-service" {
		t.Errorf("Destination.Host = %v, want mirror-service", mc.Destination.Host)
	}
	if mc.Percentage != 10 {
		t.Errorf("Percentage = %v, want 10", mc.Percentage)
	}
}

func TestCircuitBreakerConfig_Fields(t *testing.T) {
	cb := CircuitBreakerConfig{
		Enabled:          true,
		Threshold:        5,
		Timeout:          Duration("30s"),
		HalfOpenRequests: 3,
	}

	if !cb.Enabled {
		t.Error("Enabled should be true")
	}
	if cb.Threshold != 5 {
		t.Errorf("Threshold = %v, want 5", cb.Threshold)
	}
	if cb.Timeout != Duration("30s") {
		t.Errorf("Timeout = %v, want 30s", cb.Timeout)
	}
	if cb.HalfOpenRequests != 3 {
		t.Errorf("HalfOpenRequests = %v, want 3", cb.HalfOpenRequests)
	}
}

func TestLoadBalancerAlgorithm_Constants(t *testing.T) {
	tests := []struct {
		name      string
		algorithm LoadBalancerAlgorithm
		want      string
	}{
		{
			name:      "roundRobin",
			algorithm: LoadBalancerRoundRobin,
			want:      "roundRobin",
		},
		{
			name:      "weighted",
			algorithm: LoadBalancerWeighted,
			want:      "weighted",
		},
		{
			name:      "leastConn",
			algorithm: LoadBalancerLeastConn,
			want:      "leastConn",
		},
		{
			name:      "random",
			algorithm: LoadBalancerRandom,
			want:      "random",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := string(tt.algorithm); got != tt.want {
				t.Errorf("LoadBalancerAlgorithm = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadBalancerConfig_Fields(t *testing.T) {
	lb := LoadBalancerConfig{
		Algorithm: LoadBalancerRoundRobin,
	}

	if lb.Algorithm != LoadBalancerRoundRobin {
		t.Errorf("Algorithm = %v, want roundRobin", lb.Algorithm)
	}
}

// Tests for AuthenticationConfig and related types

func TestAuthenticationConfig_Fields(t *testing.T) {
	tests := []struct {
		name string
		auth AuthenticationConfig
	}{
		{
			name: "disabled authentication",
			auth: AuthenticationConfig{
				Enabled: false,
			},
		},
		{
			name: "enabled with JWT",
			auth: AuthenticationConfig{
				Enabled: true,
				JWT: &JWTAuthConfig{
					Enabled:   true,
					Issuer:    "https://issuer.example.com",
					JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
					Algorithm: "RS256",
				},
			},
		},
		{
			name: "enabled with API key",
			auth: AuthenticationConfig{
				Enabled: true,
				APIKey: &APIKeyAuthConfig{
					Enabled: true,
					Header:  "X-API-Key",
				},
			},
		},
		{
			name: "enabled with mTLS",
			auth: AuthenticationConfig{
				Enabled: true,
				MTLS: &MTLSAuthConfig{
					Enabled:         true,
					CAFile:          "/certs/ca.crt",
					ExtractIdentity: "cn",
				},
			},
		},
		{
			name: "enabled with OIDC",
			auth: AuthenticationConfig{
				Enabled: true,
				OIDC: &OIDCAuthConfig{
					Enabled: true,
					Providers: []OIDCProviderConfig{
						{
							Name:      "keycloak",
							IssuerURL: "https://keycloak.example.com/realms/myrealm",
							ClientID:  "my-client",
						},
					},
				},
			},
		},
		{
			name: "allow anonymous",
			auth: AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
			},
		},
		{
			name: "with skip paths",
			auth: AuthenticationConfig{
				Enabled:   true,
				SkipPaths: []string{"/health", "/metrics"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the auth config is properly set
			if tt.auth.Enabled && tt.auth.JWT != nil && !tt.auth.JWT.Enabled {
				t.Error("JWT should be enabled when configured")
			}
		})
	}
}

func TestJWTAuthConfig_Fields(t *testing.T) {
	jwt := JWTAuthConfig{
		Enabled:   true,
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"api", "web"},
		JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
		Secret:    "my-secret",
		PublicKey: "-----BEGIN PUBLIC KEY-----\n...",
		Algorithm: "RS256",
		ClaimMapping: &ClaimMappingConfig{
			Roles:       "roles",
			Permissions: "permissions",
			Groups:      "groups",
			Scopes:      "scope",
			Email:       "email",
			Name:        "name",
		},
	}

	if !jwt.Enabled {
		t.Error("Enabled should be true")
	}
	if jwt.Issuer != "https://issuer.example.com" {
		t.Errorf("Issuer = %v, want https://issuer.example.com", jwt.Issuer)
	}
	if len(jwt.Audience) != 2 {
		t.Errorf("Audience length = %v, want 2", len(jwt.Audience))
	}
	if jwt.JWKSURL != "https://issuer.example.com/.well-known/jwks.json" {
		t.Errorf("JWKSURL = %v, want https://issuer.example.com/.well-known/jwks.json", jwt.JWKSURL)
	}
	if jwt.Algorithm != "RS256" {
		t.Errorf("Algorithm = %v, want RS256", jwt.Algorithm)
	}
	if jwt.ClaimMapping == nil {
		t.Fatal("ClaimMapping should not be nil")
	}
	if jwt.ClaimMapping.Roles != "roles" {
		t.Errorf("ClaimMapping.Roles = %v, want roles", jwt.ClaimMapping.Roles)
	}
}

func TestJWTAuthConfig_Algorithms(t *testing.T) {
	algorithms := []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			jwt := JWTAuthConfig{
				Enabled:   true,
				Algorithm: alg,
			}
			if jwt.Algorithm != alg {
				t.Errorf("Algorithm = %v, want %v", jwt.Algorithm, alg)
			}
		})
	}
}

func TestClaimMappingConfig_Fields(t *testing.T) {
	cm := ClaimMappingConfig{
		Roles:       "roles",
		Permissions: "permissions",
		Groups:      "groups",
		Scopes:      "scope",
		Email:       "email",
		Name:        "name",
	}

	if cm.Roles != "roles" {
		t.Errorf("Roles = %v, want roles", cm.Roles)
	}
	if cm.Permissions != "permissions" {
		t.Errorf("Permissions = %v, want permissions", cm.Permissions)
	}
	if cm.Groups != "groups" {
		t.Errorf("Groups = %v, want groups", cm.Groups)
	}
	if cm.Scopes != "scope" {
		t.Errorf("Scopes = %v, want scope", cm.Scopes)
	}
	if cm.Email != "email" {
		t.Errorf("Email = %v, want email", cm.Email)
	}
	if cm.Name != "name" {
		t.Errorf("Name = %v, want name", cm.Name)
	}
}

func TestAPIKeyAuthConfig_Fields(t *testing.T) {
	apiKey := APIKeyAuthConfig{
		Enabled:       true,
		Header:        "X-API-Key",
		Query:         "api_key",
		HashAlgorithm: "sha256",
		VaultPath:     "secret/data/api-keys",
	}

	if !apiKey.Enabled {
		t.Error("Enabled should be true")
	}
	if apiKey.Header != "X-API-Key" {
		t.Errorf("Header = %v, want X-API-Key", apiKey.Header)
	}
	if apiKey.Query != "api_key" {
		t.Errorf("Query = %v, want api_key", apiKey.Query)
	}
	if apiKey.HashAlgorithm != "sha256" {
		t.Errorf("HashAlgorithm = %v, want sha256", apiKey.HashAlgorithm)
	}
	if apiKey.VaultPath != "secret/data/api-keys" {
		t.Errorf("VaultPath = %v, want secret/data/api-keys", apiKey.VaultPath)
	}
}

func TestAPIKeyAuthConfig_HashAlgorithms(t *testing.T) {
	algorithms := []string{"sha256", "sha512", "bcrypt"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			apiKey := APIKeyAuthConfig{
				Enabled:       true,
				HashAlgorithm: alg,
			}
			if apiKey.HashAlgorithm != alg {
				t.Errorf("HashAlgorithm = %v, want %v", apiKey.HashAlgorithm, alg)
			}
		})
	}
}

func TestMTLSAuthConfig_Fields(t *testing.T) {
	mtls := MTLSAuthConfig{
		Enabled:         true,
		CAFile:          "/certs/ca.crt",
		ExtractIdentity: "cn",
		AllowedCNs:      []string{"client1", "client2"},
		AllowedOUs:      []string{"engineering", "operations"},
	}

	if !mtls.Enabled {
		t.Error("Enabled should be true")
	}
	if mtls.CAFile != "/certs/ca.crt" {
		t.Errorf("CAFile = %v, want /certs/ca.crt", mtls.CAFile)
	}
	if mtls.ExtractIdentity != "cn" {
		t.Errorf("ExtractIdentity = %v, want cn", mtls.ExtractIdentity)
	}
	if len(mtls.AllowedCNs) != 2 {
		t.Errorf("AllowedCNs length = %v, want 2", len(mtls.AllowedCNs))
	}
	if len(mtls.AllowedOUs) != 2 {
		t.Errorf("AllowedOUs length = %v, want 2", len(mtls.AllowedOUs))
	}
}

func TestMTLSAuthConfig_ExtractIdentityOptions(t *testing.T) {
	options := []string{"cn", "san", "ou"}

	for _, opt := range options {
		t.Run(opt, func(t *testing.T) {
			mtls := MTLSAuthConfig{
				Enabled:         true,
				ExtractIdentity: opt,
			}
			if mtls.ExtractIdentity != opt {
				t.Errorf("ExtractIdentity = %v, want %v", mtls.ExtractIdentity, opt)
			}
		})
	}
}

func TestOIDCAuthConfig_Fields(t *testing.T) {
	oidc := OIDCAuthConfig{
		Enabled: true,
		Providers: []OIDCProviderConfig{
			{
				Name:         "keycloak",
				IssuerURL:    "https://keycloak.example.com/realms/myrealm",
				ClientID:     "my-client",
				ClientSecret: "my-secret",
				Scopes:       []string{"openid", "profile", "email"},
			},
			{
				Name:      "google",
				IssuerURL: "https://accounts.google.com",
				ClientID:  "google-client",
				ClientSecretRef: &SecretKeySelector{
					Name: "google-secret",
					Key:  "client-secret",
				},
			},
		},
	}

	if !oidc.Enabled {
		t.Error("Enabled should be true")
	}
	if len(oidc.Providers) != 2 {
		t.Fatalf("Providers length = %v, want 2", len(oidc.Providers))
	}
	if oidc.Providers[0].Name != "keycloak" {
		t.Errorf("Providers[0].Name = %v, want keycloak", oidc.Providers[0].Name)
	}
	if oidc.Providers[1].ClientSecretRef == nil {
		t.Error("Providers[1].ClientSecretRef should not be nil")
	}
}

func TestOIDCProviderConfig_Fields(t *testing.T) {
	provider := OIDCProviderConfig{
		Name:         "keycloak",
		IssuerURL:    "https://keycloak.example.com/realms/myrealm",
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		ClientSecretRef: &SecretKeySelector{
			Name: "oidc-secret",
			Key:  "client-secret",
		},
		Scopes: []string{"openid", "profile", "email"},
	}

	if provider.Name != "keycloak" {
		t.Errorf("Name = %v, want keycloak", provider.Name)
	}
	if provider.IssuerURL != "https://keycloak.example.com/realms/myrealm" {
		t.Errorf("IssuerURL = %v, want https://keycloak.example.com/realms/myrealm", provider.IssuerURL)
	}
	if provider.ClientID != "my-client" {
		t.Errorf("ClientID = %v, want my-client", provider.ClientID)
	}
	if provider.ClientSecret != "my-secret" {
		t.Errorf("ClientSecret = %v, want my-secret", provider.ClientSecret)
	}
	if provider.ClientSecretRef == nil {
		t.Fatal("ClientSecretRef should not be nil")
	}
	if len(provider.Scopes) != 3 {
		t.Errorf("Scopes length = %v, want 3", len(provider.Scopes))
	}
}

// Tests for AuthorizationConfig and related types

func TestAuthorizationConfig_Fields(t *testing.T) {
	tests := []struct {
		name  string
		authz AuthorizationConfig
	}{
		{
			name: "disabled authorization",
			authz: AuthorizationConfig{
				Enabled: false,
			},
		},
		{
			name: "enabled with RBAC",
			authz: AuthorizationConfig{
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
		{
			name: "enabled with ABAC",
			authz: AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				ABAC: &ABACConfig{
					Enabled: true,
					Policies: []ABACPolicyConfig{
						{
							Name:       "owner-policy",
							Expression: "request.user == resource.owner",
							Effect:     "allow",
						},
					},
				},
			},
		},
		{
			name: "enabled with External",
			authz: AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				External: &ExternalAuthzConfig{
					Enabled: true,
					OPA: &OPAAuthzConfig{
						URL:    "http://opa:8181/v1/data/authz/allow",
						Policy: "authz/allow",
					},
				},
			},
		},
		{
			name: "with skip paths",
			authz: AuthorizationConfig{
				Enabled:   true,
				SkipPaths: []string{"/health", "/metrics"},
			},
		},
		{
			name: "with cache",
			authz: AuthorizationConfig{
				Enabled: true,
				Cache: &AuthzCacheConfig{
					Enabled: true,
					TTL:     Duration("5m"),
					MaxSize: 1000,
					Type:    "memory",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the authz config is properly set
			if tt.authz.Enabled && tt.authz.RBAC != nil && !tt.authz.RBAC.Enabled {
				t.Error("RBAC should be enabled when configured")
			}
		})
	}
}

func TestAuthorizationConfig_DefaultPolicies(t *testing.T) {
	policies := []string{"allow", "deny"}

	for _, policy := range policies {
		t.Run(policy, func(t *testing.T) {
			authz := AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: policy,
			}
			if authz.DefaultPolicy != policy {
				t.Errorf("DefaultPolicy = %v, want %v", authz.DefaultPolicy, policy)
			}
		})
	}
}

func TestRBACConfig_Fields(t *testing.T) {
	rbac := RBACConfig{
		Enabled: true,
		Policies: []RBACPolicyConfig{
			{
				Name:      "admin-policy",
				Roles:     []string{"admin", "superadmin"},
				Resources: []string{"/api/*", "/admin/*"},
				Actions:   []string{"GET", "POST", "PUT", "DELETE"},
				Effect:    "allow",
				Priority:  100,
			},
			{
				Name:      "user-policy",
				Roles:     []string{"user"},
				Resources: []string{"/api/users/*"},
				Actions:   []string{"GET"},
				Effect:    "allow",
				Priority:  50,
			},
		},
		RoleHierarchy: map[string][]string{
			"superadmin": {"admin", "user"},
			"admin":      {"user"},
		},
	}

	if !rbac.Enabled {
		t.Error("Enabled should be true")
	}
	if len(rbac.Policies) != 2 {
		t.Fatalf("Policies length = %v, want 2", len(rbac.Policies))
	}
	if rbac.Policies[0].Name != "admin-policy" {
		t.Errorf("Policies[0].Name = %v, want admin-policy", rbac.Policies[0].Name)
	}
	if len(rbac.RoleHierarchy) != 2 {
		t.Errorf("RoleHierarchy length = %v, want 2", len(rbac.RoleHierarchy))
	}
	if len(rbac.RoleHierarchy["superadmin"]) != 2 {
		t.Errorf("RoleHierarchy[superadmin] length = %v, want 2", len(rbac.RoleHierarchy["superadmin"]))
	}
}

func TestRBACPolicyConfig_Fields(t *testing.T) {
	policy := RBACPolicyConfig{
		Name:      "test-policy",
		Roles:     []string{"admin", "editor"},
		Resources: []string{"/api/posts/*", "/api/comments/*"},
		Actions:   []string{"GET", "POST", "PUT"},
		Effect:    "allow",
		Priority:  75,
	}

	if policy.Name != "test-policy" {
		t.Errorf("Name = %v, want test-policy", policy.Name)
	}
	if len(policy.Roles) != 2 {
		t.Errorf("Roles length = %v, want 2", len(policy.Roles))
	}
	if len(policy.Resources) != 2 {
		t.Errorf("Resources length = %v, want 2", len(policy.Resources))
	}
	if len(policy.Actions) != 3 {
		t.Errorf("Actions length = %v, want 3", len(policy.Actions))
	}
	if policy.Effect != "allow" {
		t.Errorf("Effect = %v, want allow", policy.Effect)
	}
	if policy.Priority != 75 {
		t.Errorf("Priority = %v, want 75", policy.Priority)
	}
}

func TestABACConfig_Fields(t *testing.T) {
	abac := ABACConfig{
		Enabled: true,
		Policies: []ABACPolicyConfig{
			{
				Name:       "owner-policy",
				Expression: "request.user == resource.owner",
				Resources:  []string{"/api/documents/*"},
				Actions:    []string{"GET", "PUT", "DELETE"},
				Effect:     "allow",
				Priority:   100,
			},
			{
				Name:       "department-policy",
				Expression: "request.user.department == resource.department",
				Resources:  []string{"/api/reports/*"},
				Actions:    []string{"GET"},
				Effect:     "allow",
				Priority:   50,
			},
		},
	}

	if !abac.Enabled {
		t.Error("Enabled should be true")
	}
	if len(abac.Policies) != 2 {
		t.Fatalf("Policies length = %v, want 2", len(abac.Policies))
	}
	if abac.Policies[0].Name != "owner-policy" {
		t.Errorf("Policies[0].Name = %v, want owner-policy", abac.Policies[0].Name)
	}
	if abac.Policies[0].Expression != "request.user == resource.owner" {
		t.Errorf("Policies[0].Expression = %v, want request.user == resource.owner", abac.Policies[0].Expression)
	}
}

func TestABACPolicyConfig_Fields(t *testing.T) {
	policy := ABACPolicyConfig{
		Name:       "test-abac-policy",
		Expression: "request.user.role in ['admin', 'editor'] && resource.status == 'draft'",
		Resources:  []string{"/api/articles/*"},
		Actions:    []string{"PUT", "DELETE"},
		Effect:     "allow",
		Priority:   80,
	}

	if policy.Name != "test-abac-policy" {
		t.Errorf("Name = %v, want test-abac-policy", policy.Name)
	}
	if policy.Expression == "" {
		t.Error("Expression should not be empty")
	}
	if len(policy.Resources) != 1 {
		t.Errorf("Resources length = %v, want 1", len(policy.Resources))
	}
	if len(policy.Actions) != 2 {
		t.Errorf("Actions length = %v, want 2", len(policy.Actions))
	}
	if policy.Effect != "allow" {
		t.Errorf("Effect = %v, want allow", policy.Effect)
	}
	if policy.Priority != 80 {
		t.Errorf("Priority = %v, want 80", policy.Priority)
	}
}

func TestExternalAuthzConfig_Fields(t *testing.T) {
	external := ExternalAuthzConfig{
		Enabled: true,
		OPA: &OPAAuthzConfig{
			URL:    "http://opa:8181/v1/data/authz/allow",
			Policy: "authz/allow",
			Headers: map[string]string{
				"X-Custom-Header": "value",
			},
		},
		Timeout:  Duration("5s"),
		FailOpen: false,
	}

	if !external.Enabled {
		t.Error("Enabled should be true")
	}
	if external.OPA == nil {
		t.Fatal("OPA should not be nil")
	}
	if external.OPA.URL != "http://opa:8181/v1/data/authz/allow" {
		t.Errorf("OPA.URL = %v, want http://opa:8181/v1/data/authz/allow", external.OPA.URL)
	}
	if external.Timeout != Duration("5s") {
		t.Errorf("Timeout = %v, want 5s", external.Timeout)
	}
	if external.FailOpen {
		t.Error("FailOpen should be false")
	}
}

func TestOPAAuthzConfig_Fields(t *testing.T) {
	opa := OPAAuthzConfig{
		URL:    "http://opa:8181/v1/data/authz/allow",
		Policy: "authz/allow",
		Headers: map[string]string{
			"Authorization": "Bearer token",
			"X-Request-ID":  "{{.RequestID}}",
		},
	}

	if opa.URL != "http://opa:8181/v1/data/authz/allow" {
		t.Errorf("URL = %v, want http://opa:8181/v1/data/authz/allow", opa.URL)
	}
	if opa.Policy != "authz/allow" {
		t.Errorf("Policy = %v, want authz/allow", opa.Policy)
	}
	if len(opa.Headers) != 2 {
		t.Errorf("Headers length = %v, want 2", len(opa.Headers))
	}
}

func TestAuthzCacheConfig_Fields(t *testing.T) {
	cache := AuthzCacheConfig{
		Enabled: true,
		TTL:     Duration("5m"),
		MaxSize: 10000,
		Type:    "redis",
	}

	if !cache.Enabled {
		t.Error("Enabled should be true")
	}
	if cache.TTL != Duration("5m") {
		t.Errorf("TTL = %v, want 5m", cache.TTL)
	}
	if cache.MaxSize != 10000 {
		t.Errorf("MaxSize = %v, want 10000", cache.MaxSize)
	}
	if cache.Type != "redis" {
		t.Errorf("Type = %v, want redis", cache.Type)
	}
}

func TestAuthzCacheConfig_Types(t *testing.T) {
	types := []string{"memory", "redis"}

	for _, cacheType := range types {
		t.Run(cacheType, func(t *testing.T) {
			cache := AuthzCacheConfig{
				Enabled: true,
				Type:    cacheType,
			}
			if cache.Type != cacheType {
				t.Errorf("Type = %v, want %v", cache.Type, cacheType)
			}
		})
	}
}

// Tests for BackendTransformConfig and related types

func TestBackendTransformConfig_Fields(t *testing.T) {
	transform := BackendTransformConfig{
		Request: &BackendRequestTransform{
			Template: `{"wrapped": {{.Body}}}`,
			Headers: &HeaderOperation{
				Set:    map[string]string{"X-Gateway": "avapigw"},
				Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
				Remove: []string{"X-Internal"},
			},
		},
		Response: &BackendResponseTransform{
			AllowFields: []string{"id", "name", "email"},
			DenyFields:  []string{"password", "secret"},
			FieldMappings: map[string]string{
				"user_id":    "userId",
				"created_at": "createdAt",
			},
			Headers: &HeaderOperation{
				Set: map[string]string{"X-Response-Time": "{{.ResponseTime}}"},
			},
		},
	}

	if transform.Request == nil {
		t.Fatal("Request should not be nil")
	}
	if transform.Response == nil {
		t.Fatal("Response should not be nil")
	}
	if transform.Request.Template != `{"wrapped": {{.Body}}}` {
		t.Errorf("Request.Template = %v, want {\"wrapped\": {{.Body}}}", transform.Request.Template)
	}
	if len(transform.Response.AllowFields) != 3 {
		t.Errorf("Response.AllowFields length = %v, want 3", len(transform.Response.AllowFields))
	}
}

func TestBackendRequestTransform_Fields(t *testing.T) {
	request := BackendRequestTransform{
		Template: `{"data": {{.Body}}, "timestamp": "{{.Timestamp}}"}`,
		Headers: &HeaderOperation{
			Set:    map[string]string{"Content-Type": "application/json"},
			Add:    map[string]string{"X-Forwarded-For": "{{.ClientIP}}"},
			Remove: []string{"X-Internal-Header"},
		},
	}

	if request.Template == "" {
		t.Error("Template should not be empty")
	}
	if request.Headers == nil {
		t.Fatal("Headers should not be nil")
	}
	if request.Headers.Set["Content-Type"] != "application/json" {
		t.Errorf("Headers.Set[Content-Type] = %v, want application/json", request.Headers.Set["Content-Type"])
	}
}

func TestBackendResponseTransform_Fields(t *testing.T) {
	response := BackendResponseTransform{
		AllowFields: []string{"id", "name", "email", "profile"},
		DenyFields:  []string{"password", "secret", "internal_id"},
		FieldMappings: map[string]string{
			"user_id":    "userId",
			"created_at": "createdAt",
			"updated_at": "updatedAt",
		},
		Headers: &HeaderOperation{
			Set:    map[string]string{"Cache-Control": "no-cache"},
			Remove: []string{"X-Internal-Response"},
		},
	}

	if len(response.AllowFields) != 4 {
		t.Errorf("AllowFields length = %v, want 4", len(response.AllowFields))
	}
	if len(response.DenyFields) != 3 {
		t.Errorf("DenyFields length = %v, want 3", len(response.DenyFields))
	}
	if len(response.FieldMappings) != 3 {
		t.Errorf("FieldMappings length = %v, want 3", len(response.FieldMappings))
	}
	if response.Headers == nil {
		t.Fatal("Headers should not be nil")
	}
}

func TestBackendCacheConfig_Fields(t *testing.T) {
	cache := BackendCacheConfig{
		Enabled:              true,
		TTL:                  Duration("10m"),
		KeyComponents:        []string{"path", "query", "headers.Authorization"},
		StaleWhileRevalidate: Duration("2m"),
		Type:                 "redis",
	}

	if !cache.Enabled {
		t.Error("Enabled should be true")
	}
	if cache.TTL != Duration("10m") {
		t.Errorf("TTL = %v, want 10m", cache.TTL)
	}
	if len(cache.KeyComponents) != 3 {
		t.Errorf("KeyComponents length = %v, want 3", len(cache.KeyComponents))
	}
	if cache.StaleWhileRevalidate != Duration("2m") {
		t.Errorf("StaleWhileRevalidate = %v, want 2m", cache.StaleWhileRevalidate)
	}
	if cache.Type != "redis" {
		t.Errorf("Type = %v, want redis", cache.Type)
	}
}

func TestBackendCacheConfig_Types(t *testing.T) {
	types := []string{"memory", "redis"}

	for _, cacheType := range types {
		t.Run(cacheType, func(t *testing.T) {
			cache := BackendCacheConfig{
				Enabled: true,
				Type:    cacheType,
			}
			if cache.Type != cacheType {
				t.Errorf("Type = %v, want %v", cache.Type, cacheType)
			}
		})
	}
}

func TestBackendEncodingConfig_Fields(t *testing.T) {
	encoding := BackendEncodingConfig{
		Request: &BackendEncodingSettings{
			ContentType: "application/json",
			Compression: "gzip",
		},
		Response: &BackendEncodingSettings{
			ContentType: "application/json",
			Compression: "br",
		},
	}

	if encoding.Request == nil {
		t.Fatal("Request should not be nil")
	}
	if encoding.Response == nil {
		t.Fatal("Response should not be nil")
	}
	if encoding.Request.ContentType != "application/json" {
		t.Errorf("Request.ContentType = %v, want application/json", encoding.Request.ContentType)
	}
	if encoding.Request.Compression != "gzip" {
		t.Errorf("Request.Compression = %v, want gzip", encoding.Request.Compression)
	}
	if encoding.Response.Compression != "br" {
		t.Errorf("Response.Compression = %v, want br", encoding.Response.Compression)
	}
}

func TestBackendEncodingSettings_Fields(t *testing.T) {
	settings := BackendEncodingSettings{
		ContentType: "application/xml",
		Compression: "deflate",
	}

	if settings.ContentType != "application/xml" {
		t.Errorf("ContentType = %v, want application/xml", settings.ContentType)
	}
	if settings.Compression != "deflate" {
		t.Errorf("Compression = %v, want deflate", settings.Compression)
	}
}

func TestBackendEncodingSettings_CompressionTypes(t *testing.T) {
	compressions := []string{"gzip", "deflate", "br", "none"}

	for _, compression := range compressions {
		t.Run(compression, func(t *testing.T) {
			settings := BackendEncodingSettings{
				Compression: compression,
			}
			if settings.Compression != compression {
				t.Errorf("Compression = %v, want %v", settings.Compression, compression)
			}
		})
	}
}

// Tests for GRPCBackendTransformConfig and related types

func TestGRPCBackendTransformConfig_Fields(t *testing.T) {
	transform := GRPCBackendTransformConfig{
		FieldMask: &GRPCFieldMaskConfig{
			Paths: []string{"user.id", "user.name", "user.email"},
		},
		Metadata: &GRPCMetadataManipulation{
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

	if transform.FieldMask == nil {
		t.Fatal("FieldMask should not be nil")
	}
	if transform.Metadata == nil {
		t.Fatal("Metadata should not be nil")
	}
	if len(transform.FieldMask.Paths) != 3 {
		t.Errorf("FieldMask.Paths length = %v, want 3", len(transform.FieldMask.Paths))
	}
	if len(transform.Metadata.Static) != 2 {
		t.Errorf("Metadata.Static length = %v, want 2", len(transform.Metadata.Static))
	}
	if len(transform.Metadata.Dynamic) != 2 {
		t.Errorf("Metadata.Dynamic length = %v, want 2", len(transform.Metadata.Dynamic))
	}
}

func TestGRPCFieldMaskConfig_Fields(t *testing.T) {
	fieldMask := GRPCFieldMaskConfig{
		Paths: []string{
			"user.id",
			"user.name",
			"user.profile.avatar",
			"user.settings.notifications",
		},
	}

	if len(fieldMask.Paths) != 4 {
		t.Fatalf("Paths length = %v, want 4", len(fieldMask.Paths))
	}
	if fieldMask.Paths[0] != "user.id" {
		t.Errorf("Paths[0] = %v, want user.id", fieldMask.Paths[0])
	}
	if fieldMask.Paths[2] != "user.profile.avatar" {
		t.Errorf("Paths[2] = %v, want user.profile.avatar", fieldMask.Paths[2])
	}
}

func TestGRPCMetadataManipulation_Fields(t *testing.T) {
	metadata := GRPCMetadataManipulation{
		Static: map[string]string{
			"x-source":      "gateway",
			"x-version":     "v1",
			"x-environment": "production",
		},
		Dynamic: map[string]string{
			"x-request-id": "{{.RequestID}}",
			"x-timestamp":  "{{.Timestamp}}",
			"x-client-ip":  "{{.ClientIP}}",
		},
	}

	if len(metadata.Static) != 3 {
		t.Errorf("Static length = %v, want 3", len(metadata.Static))
	}
	if metadata.Static["x-source"] != "gateway" {
		t.Errorf("Static[x-source] = %v, want gateway", metadata.Static["x-source"])
	}
	if len(metadata.Dynamic) != 3 {
		t.Errorf("Dynamic length = %v, want 3", len(metadata.Dynamic))
	}
	if metadata.Dynamic["x-request-id"] != "{{.RequestID}}" {
		t.Errorf("Dynamic[x-request-id] = %v, want {{.RequestID}}", metadata.Dynamic["x-request-id"])
	}
}

func TestCondition_StatusValues(t *testing.T) {
	tests := []struct {
		name   string
		status metav1.ConditionStatus
	}{
		{
			name:   "True",
			status: metav1.ConditionTrue,
		},
		{
			name:   "False",
			status: metav1.ConditionFalse,
		},
		{
			name:   "Unknown",
			status: metav1.ConditionUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := Condition{
				Type:               ConditionReady,
				Status:             tt.status,
				Reason:             ReasonReconciled,
				LastTransitionTime: metav1.Now(),
			}
			if condition.Status != tt.status {
				t.Errorf("Status = %v, want %v", condition.Status, tt.status)
			}
		})
	}
}

func TestAppliedGateway_TimeTracking(t *testing.T) {
	before := metav1.Now()
	time.Sleep(10 * time.Millisecond)
	gateway := AppliedGateway{
		Name:        "test-gateway",
		Namespace:   "test-namespace",
		LastApplied: metav1.Now(),
	}
	time.Sleep(10 * time.Millisecond)
	after := metav1.Now()

	if gateway.LastApplied.Before(&before) {
		t.Error("LastApplied should be after before time")
	}
	if gateway.LastApplied.After(after.Time) {
		t.Error("LastApplied should be before after time")
	}
}

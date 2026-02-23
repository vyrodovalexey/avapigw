package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGraphQLBackend_TypeMeta(t *testing.T) {
	backend := &GraphQLBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GraphQLBackend",
		},
	}

	if backend.APIVersion != "avapigw.io/v1alpha1" {
		t.Errorf("APIVersion = %v, want avapigw.io/v1alpha1", backend.APIVersion)
	}
	if backend.Kind != "GraphQLBackend" {
		t.Errorf("Kind = %v, want GraphQLBackend", backend.Kind)
	}
}

func TestGraphQLBackend_ObjectMeta(t *testing.T) {
	backend := &GraphQLBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-graphql-backend",
			Namespace: "test-namespace",
		},
	}

	if backend.Name != "test-graphql-backend" {
		t.Errorf("Name = %v, want test-graphql-backend", backend.Name)
	}
	if backend.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", backend.Namespace)
	}
}

func TestGraphQLBackendSpec_Hosts(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{
			{
				Address: "graphql-service.default.svc.cluster.local",
				Port:    4000,
				Weight:  1,
			},
		},
	}

	if len(spec.Hosts) != 1 {
		t.Fatalf("Hosts length = %v, want 1", len(spec.Hosts))
	}
	if spec.Hosts[0].Address != "graphql-service.default.svc.cluster.local" {
		t.Errorf("Hosts[0].Address = %v, want graphql-service.default.svc.cluster.local", spec.Hosts[0].Address)
	}
	if spec.Hosts[0].Port != 4000 {
		t.Errorf("Hosts[0].Port = %v, want 4000", spec.Hosts[0].Port)
	}
}

func TestGraphQLBackendSpec_HealthCheck(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		HealthCheck: &HealthCheckConfig{
			Path:     "/health",
			Interval: Duration("10s"),
			Timeout:  Duration("5s"),
		},
	}

	if spec.HealthCheck == nil {
		t.Fatal("HealthCheck should not be nil")
	}
	if spec.HealthCheck.Path != "/health" {
		t.Errorf("HealthCheck.Path = %v, want /health", spec.HealthCheck.Path)
	}
	if spec.HealthCheck.Interval != Duration("10s") {
		t.Errorf("HealthCheck.Interval = %v, want 10s", spec.HealthCheck.Interval)
	}
	if spec.HealthCheck.Timeout != Duration("5s") {
		t.Errorf("HealthCheck.Timeout = %v, want 5s", spec.HealthCheck.Timeout)
	}
}

func TestGraphQLBackendSpec_LoadBalancer(t *testing.T) {
	tests := []struct {
		name      string
		algorithm LoadBalancerAlgorithm
	}{
		{"roundRobin", LoadBalancerRoundRobin},
		{"weighted", LoadBalancerWeighted},
		{"leastConn", LoadBalancerLeastConn},
		{"random", LoadBalancerRandom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := GraphQLBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
				LoadBalancer: &LoadBalancerConfig{
					Algorithm: tt.algorithm,
				},
			}

			if spec.LoadBalancer == nil {
				t.Fatal("LoadBalancer should not be nil")
			}
			if spec.LoadBalancer.Algorithm != tt.algorithm {
				t.Errorf("LoadBalancer.Algorithm = %v, want %v", spec.LoadBalancer.Algorithm, tt.algorithm)
			}
		})
	}
}

func TestGraphQLBackendSpec_TLS(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		TLS: &BackendTLSConfig{
			Enabled:    true,
			Mode:       "MUTUAL",
			MinVersion: "TLS12",
			Vault: &VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "graphql-client",
				CommonName: "gateway-graphql-client",
			},
		},
	}

	if spec.TLS == nil {
		t.Fatal("TLS should not be nil")
	}
	if !spec.TLS.Enabled {
		t.Error("TLS.Enabled should be true")
	}
	if spec.TLS.Mode != "MUTUAL" {
		t.Errorf("TLS.Mode = %v, want MUTUAL", spec.TLS.Mode)
	}
	if spec.TLS.Vault == nil {
		t.Fatal("TLS.Vault should not be nil")
	}
}

func TestGraphQLBackendSpec_CircuitBreaker(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled:          true,
			Threshold:        5,
			Timeout:          Duration("30s"),
			HalfOpenRequests: 3,
		},
	}

	if spec.CircuitBreaker == nil {
		t.Fatal("CircuitBreaker should not be nil")
	}
	if !spec.CircuitBreaker.Enabled {
		t.Error("CircuitBreaker.Enabled should be true")
	}
	if spec.CircuitBreaker.Threshold != 5 {
		t.Errorf("CircuitBreaker.Threshold = %v, want 5", spec.CircuitBreaker.Threshold)
	}
}

func TestGraphQLBackendSpec_Authentication(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
			JWT: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "test-token",
			},
		},
	}

	if spec.Authentication == nil {
		t.Fatal("Authentication should not be nil")
	}
	if spec.Authentication.Type != "jwt" {
		t.Errorf("Authentication.Type = %v, want jwt", spec.Authentication.Type)
	}
}

func TestGraphQLBackendSpec_MaxSessions(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 500,
			QueueSize:     100,
			QueueTimeout:  Duration("30s"),
		},
	}

	if spec.MaxSessions == nil {
		t.Fatal("MaxSessions should not be nil")
	}
	if !spec.MaxSessions.Enabled {
		t.Error("MaxSessions.Enabled should be true")
	}
	if spec.MaxSessions.MaxConcurrent != 500 {
		t.Errorf("MaxSessions.MaxConcurrent = %v, want 500", spec.MaxSessions.MaxConcurrent)
	}
}

func TestGraphQLBackendSpec_RateLimit(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
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

func TestGraphQLBackendSpec_Cache(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		Cache: &BackendCacheConfig{
			Enabled: true,
			TTL:     Duration("10m"),
			Type:    "memory",
		},
	}

	if spec.Cache == nil {
		t.Fatal("Cache should not be nil")
	}
	if !spec.Cache.Enabled {
		t.Error("Cache.Enabled should be true")
	}
}

func TestGraphQLBackendSpec_Encoding(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 4000}},
		Encoding: &BackendEncodingConfig{
			Request: &BackendEncodingSettings{
				ContentType: "application/json",
				Compression: "gzip",
			},
		},
	}

	if spec.Encoding == nil {
		t.Fatal("Encoding should not be nil")
	}
	if spec.Encoding.Request == nil {
		t.Fatal("Encoding.Request should not be nil")
	}
}

func TestGraphQLBackendStatus_Conditions(t *testing.T) {
	now := metav1.Now()
	status := GraphQLBackendStatus{
		Conditions: []Condition{
			{
				Type:               ConditionReady,
				Status:             metav1.ConditionTrue,
				Reason:             ReasonReconciled,
				Message:            "Backend successfully configured",
				LastTransitionTime: now,
			},
			{
				Type:               ConditionHealthy,
				Status:             metav1.ConditionTrue,
				Reason:             ReasonHealthCheckOK,
				Message:            "All hosts are healthy",
				LastTransitionTime: now,
			},
		},
		ObservedGeneration: 1,
		HealthyHosts:       2,
		TotalHosts:         2,
		LastHealthCheck:    &now,
	}

	if len(status.Conditions) != 2 {
		t.Fatalf("Conditions length = %v, want 2", len(status.Conditions))
	}
	if status.Conditions[0].Type != ConditionReady {
		t.Errorf("Conditions[0].Type = %v, want Ready", status.Conditions[0].Type)
	}
	if status.HealthyHosts != 2 {
		t.Errorf("HealthyHosts = %v, want 2", status.HealthyHosts)
	}
	if status.TotalHosts != 2 {
		t.Errorf("TotalHosts = %v, want 2", status.TotalHosts)
	}
}

func TestGraphQLBackendList_Items(t *testing.T) {
	list := &GraphQLBackendList{
		Items: []GraphQLBackend{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "graphql-backend-1",
					Namespace: "default",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "graphql-backend-2",
					Namespace: "default",
				},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Fatalf("Items length = %v, want 2", len(list.Items))
	}
	if list.Items[0].Name != "graphql-backend-1" {
		t.Errorf("Items[0].Name = %v, want graphql-backend-1", list.Items[0].Name)
	}
}

func TestGraphQLBackend_FullSpec(t *testing.T) {
	now := metav1.Now()
	backend := &GraphQLBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GraphQLBackend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-graphql-backend",
			Namespace: "default",
		},
		Spec: GraphQLBackendSpec{
			Hosts: []BackendHost{
				{Address: "graphql-service.default.svc.cluster.local", Port: 4000, Weight: 1},
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
				Enabled: true,
				Mode:    "SIMPLE",
			},
			CircuitBreaker: &CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
			},
			Authentication: &BackendAuthConfig{
				Type: "jwt",
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 500,
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
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
			},
			ObservedGeneration: 1,
			HealthyHosts:       1,
			TotalHosts:         1,
			LastHealthCheck:    &now,
		},
	}

	if backend.Name != "full-graphql-backend" {
		t.Errorf("Name = %v, want full-graphql-backend", backend.Name)
	}
	if len(backend.Spec.Hosts) != 1 {
		t.Errorf("Spec.Hosts length = %v, want 1", len(backend.Spec.Hosts))
	}
	if backend.Spec.HealthCheck == nil {
		t.Error("Spec.HealthCheck should not be nil")
	}
	if backend.Spec.LoadBalancer == nil {
		t.Error("Spec.LoadBalancer should not be nil")
	}
	if backend.Spec.TLS == nil {
		t.Error("Spec.TLS should not be nil")
	}
	if backend.Spec.CircuitBreaker == nil {
		t.Error("Spec.CircuitBreaker should not be nil")
	}
	if backend.Spec.Authentication == nil {
		t.Error("Spec.Authentication should not be nil")
	}
	if backend.Spec.MaxSessions == nil {
		t.Error("Spec.MaxSessions should not be nil")
	}
	if backend.Spec.RateLimit == nil {
		t.Error("Spec.RateLimit should not be nil")
	}
}

func TestGraphQLBackendSpec_MultipleHosts(t *testing.T) {
	spec := GraphQLBackendSpec{
		Hosts: []BackendHost{
			{Address: "graphql-1.default.svc.cluster.local", Port: 4000, Weight: 33},
			{Address: "graphql-2.default.svc.cluster.local", Port: 4000, Weight: 33},
			{Address: "graphql-3.default.svc.cluster.local", Port: 4000, Weight: 34},
		},
	}

	if len(spec.Hosts) != 3 {
		t.Fatalf("Hosts length = %v, want 3", len(spec.Hosts))
	}

	totalWeight := 0
	for _, host := range spec.Hosts {
		totalWeight += host.Weight
	}
	if totalWeight != 100 {
		t.Errorf("Total weight = %v, want 100", totalWeight)
	}
}

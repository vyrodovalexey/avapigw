// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGRPCBackend_TypeMeta(t *testing.T) {
	backend := &GRPCBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCBackend",
		},
	}

	if backend.APIVersion != "avapigw.io/v1alpha1" {
		t.Errorf("APIVersion = %v, want avapigw.io/v1alpha1", backend.APIVersion)
	}
	if backend.Kind != "GRPCBackend" {
		t.Errorf("Kind = %v, want GRPCBackend", backend.Kind)
	}
}

func TestGRPCBackend_ObjectMeta(t *testing.T) {
	backend := &GRPCBackend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-grpc-backend",
			Namespace: "test-namespace",
		},
	}

	if backend.Name != "test-grpc-backend" {
		t.Errorf("Name = %v, want test-grpc-backend", backend.Name)
	}
	if backend.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", backend.Namespace)
	}
}

func TestGRPCBackendSpec_Hosts(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{
			{
				Address: "grpc-service.default.svc.cluster.local",
				Port:    9000,
				Weight:  1,
			},
		},
	}

	if len(spec.Hosts) != 1 {
		t.Fatalf("Hosts length = %v, want 1", len(spec.Hosts))
	}
	if spec.Hosts[0].Address != "grpc-service.default.svc.cluster.local" {
		t.Errorf("Hosts[0].Address = %v, want grpc-service.default.svc.cluster.local", spec.Hosts[0].Address)
	}
	if spec.Hosts[0].Port != 9000 {
		t.Errorf("Hosts[0].Port = %v, want 9000", spec.Hosts[0].Port)
	}
}

func TestGRPCBackendSpec_HealthCheck(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			Service:            "",
			Interval:           Duration("10s"),
			Timeout:            Duration("5s"),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	if spec.HealthCheck == nil {
		t.Fatal("HealthCheck should not be nil")
	}
	if !spec.HealthCheck.Enabled {
		t.Error("HealthCheck.Enabled should be true")
	}
	if spec.HealthCheck.Service != "" {
		t.Errorf("HealthCheck.Service = %v, want empty string", spec.HealthCheck.Service)
	}
	if spec.HealthCheck.Interval != Duration("10s") {
		t.Errorf("HealthCheck.Interval = %v, want 10s", spec.HealthCheck.Interval)
	}
	if spec.HealthCheck.Timeout != Duration("5s") {
		t.Errorf("HealthCheck.Timeout = %v, want 5s", spec.HealthCheck.Timeout)
	}
	if spec.HealthCheck.HealthyThreshold != 2 {
		t.Errorf("HealthCheck.HealthyThreshold = %v, want 2", spec.HealthCheck.HealthyThreshold)
	}
	if spec.HealthCheck.UnhealthyThreshold != 3 {
		t.Errorf("HealthCheck.UnhealthyThreshold = %v, want 3", spec.HealthCheck.UnhealthyThreshold)
	}
}

func TestGRPCHealthCheckConfig_WithService(t *testing.T) {
	hc := GRPCHealthCheckConfig{
		Enabled:            true,
		Service:            "api.v1.UserService",
		Interval:           Duration("15s"),
		Timeout:            Duration("3s"),
		HealthyThreshold:   3,
		UnhealthyThreshold: 5,
	}

	if !hc.Enabled {
		t.Error("Enabled should be true")
	}
	if hc.Service != "api.v1.UserService" {
		t.Errorf("Service = %v, want api.v1.UserService", hc.Service)
	}
	if hc.Interval != Duration("15s") {
		t.Errorf("Interval = %v, want 15s", hc.Interval)
	}
	if hc.Timeout != Duration("3s") {
		t.Errorf("Timeout = %v, want 3s", hc.Timeout)
	}
	if hc.HealthyThreshold != 3 {
		t.Errorf("HealthyThreshold = %v, want 3", hc.HealthyThreshold)
	}
	if hc.UnhealthyThreshold != 5 {
		t.Errorf("UnhealthyThreshold = %v, want 5", hc.UnhealthyThreshold)
	}
}

func TestGRPCBackendSpec_LoadBalancer(t *testing.T) {
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
			spec := GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
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

func TestGRPCBackendSpec_TLS(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		TLS: &BackendTLSConfig{
			Enabled:    true,
			Mode:       "MUTUAL",
			MinVersion: "TLS12",
			Vault: &VaultBackendTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "grpc-client",
				CommonName: "gateway-grpc-client",
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
	if !spec.TLS.Vault.Enabled {
		t.Error("TLS.Vault.Enabled should be true")
	}
}

func TestGRPCBackendSpec_ConnectionPool(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		ConnectionPool: &GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: 100,
			IdleConnTimeout: Duration("5m"),
		},
	}

	if spec.ConnectionPool == nil {
		t.Fatal("ConnectionPool should not be nil")
	}
	if spec.ConnectionPool.MaxIdleConns != 10 {
		t.Errorf("ConnectionPool.MaxIdleConns = %v, want 10", spec.ConnectionPool.MaxIdleConns)
	}
	if spec.ConnectionPool.MaxConnsPerHost != 100 {
		t.Errorf("ConnectionPool.MaxConnsPerHost = %v, want 100", spec.ConnectionPool.MaxConnsPerHost)
	}
	if spec.ConnectionPool.IdleConnTimeout != Duration("5m") {
		t.Errorf("ConnectionPool.IdleConnTimeout = %v, want 5m", spec.ConnectionPool.IdleConnTimeout)
	}
}

func TestGRPCConnectionPoolConfig_AllFields(t *testing.T) {
	cp := GRPCConnectionPoolConfig{
		MaxIdleConns:    20,
		MaxConnsPerHost: 200,
		IdleConnTimeout: Duration("10m"),
	}

	if cp.MaxIdleConns != 20 {
		t.Errorf("MaxIdleConns = %v, want 20", cp.MaxIdleConns)
	}
	if cp.MaxConnsPerHost != 200 {
		t.Errorf("MaxConnsPerHost = %v, want 200", cp.MaxConnsPerHost)
	}
	if cp.IdleConnTimeout != Duration("10m") {
		t.Errorf("IdleConnTimeout = %v, want 10m", cp.IdleConnTimeout)
	}
}

func TestGRPCBackendSpec_CircuitBreaker(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
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
	if spec.CircuitBreaker.Timeout != Duration("30s") {
		t.Errorf("CircuitBreaker.Timeout = %v, want 30s", spec.CircuitBreaker.Timeout)
	}
}

func TestGRPCBackendSpec_Authentication_JWT(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
			JWT: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &BackendOIDCConfig{
					IssuerURL: "https://keycloak.example.com/realms/myrealm",
					ClientID:  "grpc-client",
					ClientSecretRef: &SecretKeySelector{
						Name: "keycloak-secret",
						Key:  "client-secret",
					},
				},
			},
		},
	}

	if spec.Authentication == nil {
		t.Fatal("Authentication should not be nil")
	}
	if spec.Authentication.Type != "jwt" {
		t.Errorf("Authentication.Type = %v, want jwt", spec.Authentication.Type)
	}
	if spec.Authentication.JWT == nil {
		t.Fatal("Authentication.JWT should not be nil")
	}
	if !spec.Authentication.JWT.Enabled {
		t.Error("Authentication.JWT.Enabled should be true")
	}
	if spec.Authentication.JWT.OIDC == nil {
		t.Fatal("Authentication.JWT.OIDC should not be nil")
	}
}

func TestGRPCBackendStatus_Conditions(t *testing.T) {
	now := metav1.Now()
	status := GRPCBackendStatus{
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
		HealthyHosts:       1,
		TotalHosts:         1,
		LastHealthCheck:    &now,
	}

	if len(status.Conditions) != 2 {
		t.Fatalf("Conditions length = %v, want 2", len(status.Conditions))
	}
	if status.Conditions[0].Type != ConditionReady {
		t.Errorf("Conditions[0].Type = %v, want Ready", status.Conditions[0].Type)
	}
	if status.Conditions[1].Type != ConditionHealthy {
		t.Errorf("Conditions[1].Type = %v, want Healthy", status.Conditions[1].Type)
	}
	if status.ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %v, want 1", status.ObservedGeneration)
	}
	if status.HealthyHosts != 1 {
		t.Errorf("HealthyHosts = %v, want 1", status.HealthyHosts)
	}
	if status.TotalHosts != 1 {
		t.Errorf("TotalHosts = %v, want 1", status.TotalHosts)
	}
	if status.LastHealthCheck == nil {
		t.Error("LastHealthCheck should not be nil")
	}
}

func TestGRPCBackendList_Items(t *testing.T) {
	list := &GRPCBackendList{
		Items: []GRPCBackend{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-backend-1",
					Namespace: "default",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "grpc-backend-2",
					Namespace: "default",
				},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Fatalf("Items length = %v, want 2", len(list.Items))
	}
	if list.Items[0].Name != "grpc-backend-1" {
		t.Errorf("Items[0].Name = %v, want grpc-backend-1", list.Items[0].Name)
	}
}

func TestGRPCBackend_FullSpec(t *testing.T) {
	now := metav1.Now()
	backend := &GRPCBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCBackend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-grpc-backend",
			Namespace: "default",
		},
		Spec: GRPCBackendSpec{
			Hosts: []BackendHost{
				{
					Address: "grpc-service.default.svc.cluster.local",
					Port:    9000,
					Weight:  1,
				},
			},
			HealthCheck: &GRPCHealthCheckConfig{
				Enabled:            true,
				Service:            "",
				Interval:           Duration("10s"),
				Timeout:            Duration("5s"),
				HealthyThreshold:   2,
				UnhealthyThreshold: 3,
			},
			LoadBalancer: &LoadBalancerConfig{
				Algorithm: LoadBalancerRoundRobin,
			},
			TLS: &BackendTLSConfig{
				Enabled:    true,
				Mode:       "MUTUAL",
				MinVersion: "TLS12",
				Vault: &VaultBackendTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-client",
					CommonName: "gateway-grpc-client",
				},
			},
			ConnectionPool: &GRPCConnectionPoolConfig{
				MaxIdleConns:    10,
				MaxConnsPerHost: 100,
				IdleConnTimeout: Duration("5m"),
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
					OIDC: &BackendOIDCConfig{
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "grpc-client",
						ClientSecretRef: &SecretKeySelector{
							Name: "keycloak-secret",
							Key:  "client-secret",
						},
					},
				},
			},
		},
		Status: GRPCBackendStatus{
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
			ObservedGeneration: 1,
			HealthyHosts:       1,
			TotalHosts:         1,
			LastHealthCheck:    &now,
		},
	}

	// Verify all fields are set correctly
	if backend.Name != "full-grpc-backend" {
		t.Errorf("Name = %v, want full-grpc-backend", backend.Name)
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
	if backend.Spec.ConnectionPool == nil {
		t.Error("Spec.ConnectionPool should not be nil")
	}
	if backend.Spec.CircuitBreaker == nil {
		t.Error("Spec.CircuitBreaker should not be nil")
	}
	if backend.Spec.Authentication == nil {
		t.Error("Spec.Authentication should not be nil")
	}
	if len(backend.Status.Conditions) != 2 {
		t.Errorf("Status.Conditions length = %v, want 2", len(backend.Status.Conditions))
	}
	if backend.Status.HealthyHosts != 1 {
		t.Errorf("Status.HealthyHosts = %v, want 1", backend.Status.HealthyHosts)
	}
}

func TestGRPCBackendStatus_UnhealthyHosts(t *testing.T) {
	now := metav1.Now()
	status := GRPCBackendStatus{
		Conditions: []Condition{
			{
				Type:               ConditionReady,
				Status:             metav1.ConditionTrue,
				Reason:             ReasonReconciled,
				LastTransitionTime: now,
			},
			{
				Type:               ConditionHealthy,
				Status:             metav1.ConditionFalse,
				Reason:             ReasonHealthCheckFail,
				Message:            "Some hosts are unhealthy",
				LastTransitionTime: now,
			},
		},
		ObservedGeneration: 1,
		HealthyHosts:       1,
		TotalHosts:         3,
		LastHealthCheck:    &now,
	}

	if status.HealthyHosts != 1 {
		t.Errorf("HealthyHosts = %v, want 1", status.HealthyHosts)
	}
	if status.TotalHosts != 3 {
		t.Errorf("TotalHosts = %v, want 3", status.TotalHosts)
	}
	if status.Conditions[1].Status != metav1.ConditionFalse {
		t.Errorf("Conditions[1].Status = %v, want False", status.Conditions[1].Status)
	}
	if status.Conditions[1].Reason != ReasonHealthCheckFail {
		t.Errorf("Conditions[1].Reason = %v, want HealthCheckFailed", status.Conditions[1].Reason)
	}
}

func TestGRPCBackendSpec_MultipleHosts(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{
			{
				Address: "grpc-1.default.svc.cluster.local",
				Port:    9000,
				Weight:  33,
			},
			{
				Address: "grpc-2.default.svc.cluster.local",
				Port:    9000,
				Weight:  33,
			},
			{
				Address: "grpc-3.default.svc.cluster.local",
				Port:    9000,
				Weight:  34,
			},
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

// Tests for GRPCBackend with MaxSessions configuration

func TestGRPCBackendSpec_MaxSessions(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCBackendSpec
	}{
		{
			name: "basic max sessions",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				MaxSessions: &MaxSessionsConfig{
					Enabled:       true,
					MaxConcurrent: 1000,
				},
			},
		},
		{
			name: "max sessions with queue",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
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
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
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

func TestGRPCBackendSpec_MaxSessions_AllFields(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
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

// Tests for GRPCBackend with RateLimit configuration

func TestGRPCBackendSpec_RateLimit(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCBackendSpec
	}{
		{
			name: "basic rate limit",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				RateLimit: &RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 100,
					Burst:             200,
				},
			},
		},
		{
			name: "rate limit with per client",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				RateLimit: &RateLimitConfig{
					Enabled:           true,
					RequestsPerSecond: 50,
					Burst:             100,
					PerClient:         true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.RateLimit == nil {
				t.Fatal("RateLimit should not be nil")
			}
			if !tt.spec.RateLimit.Enabled {
				t.Error("RateLimit.Enabled should be true")
			}
		})
	}
}

func TestGRPCBackendSpec_RateLimit_AllFields(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		RateLimit: &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 100,
			Burst:             200,
			PerClient:         true,
		},
	}

	rl := spec.RateLimit
	if rl == nil {
		t.Fatal("RateLimit should not be nil")
	}
	if !rl.Enabled {
		t.Error("RateLimit.Enabled should be true")
	}
	if rl.RequestsPerSecond != 100 {
		t.Errorf("RateLimit.RequestsPerSecond = %v, want 100", rl.RequestsPerSecond)
	}
	if rl.Burst != 200 {
		t.Errorf("RateLimit.Burst = %v, want 200", rl.Burst)
	}
	if !rl.PerClient {
		t.Error("RateLimit.PerClient should be true")
	}
}

// Tests for GRPCBackend with Transform configuration

func TestGRPCBackendSpec_Transform(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCBackendSpec
	}{
		{
			name: "field mask only",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Transform: &GRPCBackendTransformConfig{
					FieldMask: &GRPCFieldMaskConfig{
						Paths: []string{"user.id", "user.name"},
					},
				},
			},
		},
		{
			name: "metadata only",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Transform: &GRPCBackendTransformConfig{
					Metadata: &GRPCMetadataManipulation{
						Static: map[string]string{
							"x-source": "gateway",
						},
						Dynamic: map[string]string{
							"x-request-id": "{{.RequestID}}",
						},
					},
				},
			},
		},
		{
			name: "both field mask and metadata",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Transform: &GRPCBackendTransformConfig{
					FieldMask: &GRPCFieldMaskConfig{
						Paths: []string{"user.id", "user.name", "user.email"},
					},
					Metadata: &GRPCMetadataManipulation{
						Static: map[string]string{
							"x-source":  "gateway",
							"x-version": "v1",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Transform == nil {
				t.Fatal("Transform should not be nil")
			}
		})
	}
}

func TestGRPCBackendSpec_Transform_AllFields(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		Transform: &GRPCBackendTransformConfig{
			FieldMask: &GRPCFieldMaskConfig{
				Paths: []string{"user.id", "user.name", "user.email", "user.profile.avatar"},
			},
			Metadata: &GRPCMetadataManipulation{
				Static: map[string]string{
					"x-source":      "gateway",
					"x-version":     "v1",
					"x-environment": "production",
				},
				Dynamic: map[string]string{
					"x-request-id": "{{.RequestID}}",
					"x-timestamp":  "{{.Timestamp}}",
				},
			},
		},
	}

	transform := spec.Transform
	if transform == nil {
		t.Fatal("Transform should not be nil")
	}
	if transform.FieldMask == nil {
		t.Fatal("Transform.FieldMask should not be nil")
	}
	if transform.Metadata == nil {
		t.Fatal("Transform.Metadata should not be nil")
	}
	if len(transform.FieldMask.Paths) != 4 {
		t.Errorf("Transform.FieldMask.Paths length = %v, want 4", len(transform.FieldMask.Paths))
	}
	if len(transform.Metadata.Static) != 3 {
		t.Errorf("Transform.Metadata.Static length = %v, want 3", len(transform.Metadata.Static))
	}
	if len(transform.Metadata.Dynamic) != 2 {
		t.Errorf("Transform.Metadata.Dynamic length = %v, want 2", len(transform.Metadata.Dynamic))
	}
}

// Tests for GRPCBackend with Cache configuration

func TestGRPCBackendSpec_Cache(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCBackendSpec
	}{
		{
			name: "basic cache",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Cache: &BackendCacheConfig{
					Enabled: true,
					TTL:     Duration("5m"),
				},
			},
		},
		{
			name: "cache with key components",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Cache: &BackendCacheConfig{
					Enabled:       true,
					TTL:           Duration("10m"),
					KeyComponents: []string{"service", "method", "metadata.x-tenant-id"},
				},
			},
		},
		{
			name: "redis cache",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Cache: &BackendCacheConfig{
					Enabled: true,
					TTL:     Duration("10m"),
					Type:    "redis",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Cache == nil {
				t.Fatal("Cache should not be nil")
			}
			if !tt.spec.Cache.Enabled {
				t.Error("Cache.Enabled should be true")
			}
		})
	}
}

func TestGRPCBackendSpec_Cache_AllFields(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		Cache: &BackendCacheConfig{
			Enabled:              true,
			TTL:                  Duration("10m"),
			KeyComponents:        []string{"service", "method", "metadata.x-tenant-id"},
			StaleWhileRevalidate: Duration("2m"),
			Type:                 "redis",
		},
	}

	cache := spec.Cache
	if cache == nil {
		t.Fatal("Cache should not be nil")
	}
	if !cache.Enabled {
		t.Error("Cache.Enabled should be true")
	}
	if cache.TTL != Duration("10m") {
		t.Errorf("Cache.TTL = %v, want 10m", cache.TTL)
	}
	if len(cache.KeyComponents) != 3 {
		t.Errorf("Cache.KeyComponents length = %v, want 3", len(cache.KeyComponents))
	}
	if cache.StaleWhileRevalidate != Duration("2m") {
		t.Errorf("Cache.StaleWhileRevalidate = %v, want 2m", cache.StaleWhileRevalidate)
	}
	if cache.Type != "redis" {
		t.Errorf("Cache.Type = %v, want redis", cache.Type)
	}
}

// Tests for GRPCBackend with Encoding configuration

func TestGRPCBackendSpec_Encoding(t *testing.T) {
	tests := []struct {
		name string
		spec GRPCBackendSpec
	}{
		{
			name: "request encoding only",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Encoding: &BackendEncodingConfig{
					Request: &BackendEncodingSettings{
						ContentType: "application/grpc",
						Compression: "gzip",
					},
				},
			},
		},
		{
			name: "response encoding only",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Encoding: &BackendEncodingConfig{
					Response: &BackendEncodingSettings{
						ContentType: "application/grpc",
						Compression: "none",
					},
				},
			},
		},
		{
			name: "both encodings",
			spec: GRPCBackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
				Encoding: &BackendEncodingConfig{
					Request: &BackendEncodingSettings{
						ContentType: "application/grpc",
						Compression: "gzip",
					},
					Response: &BackendEncodingSettings{
						ContentType: "application/grpc",
						Compression: "gzip",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.spec.Encoding == nil {
				t.Fatal("Encoding should not be nil")
			}
		})
	}
}

func TestGRPCBackendSpec_Encoding_AllFields(t *testing.T) {
	spec := GRPCBackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 9000}},
		Encoding: &BackendEncodingConfig{
			Request: &BackendEncodingSettings{
				ContentType: "application/grpc",
				Compression: "gzip",
			},
			Response: &BackendEncodingSettings{
				ContentType: "application/grpc+proto",
				Compression: "deflate",
			},
		},
	}

	encoding := spec.Encoding
	if encoding == nil {
		t.Fatal("Encoding should not be nil")
	}
	if encoding.Request == nil {
		t.Fatal("Encoding.Request should not be nil")
	}
	if encoding.Response == nil {
		t.Fatal("Encoding.Response should not be nil")
	}
	if encoding.Request.ContentType != "application/grpc" {
		t.Errorf("Encoding.Request.ContentType = %v, want application/grpc", encoding.Request.ContentType)
	}
	if encoding.Request.Compression != "gzip" {
		t.Errorf("Encoding.Request.Compression = %v, want gzip", encoding.Request.Compression)
	}
	if encoding.Response.Compression != "deflate" {
		t.Errorf("Encoding.Response.Compression = %v, want deflate", encoding.Response.Compression)
	}
}

// Tests for GRPCBackend with all new fields combined

func TestGRPCBackend_FullSpecWithAllNewFields(t *testing.T) {
	now := metav1.Now()
	backend := &GRPCBackend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "GRPCBackend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-grpc-backend-new-fields",
			Namespace: "default",
		},
		Spec: GRPCBackendSpec{
			Hosts: []BackendHost{
				{
					Address: "grpc-service.default.svc.cluster.local",
					Port:    9000,
					Weight:  1,
				},
			},
			HealthCheck: &GRPCHealthCheckConfig{
				Enabled:  true,
				Interval: Duration("10s"),
				Timeout:  Duration("5s"),
			},
			LoadBalancer: &LoadBalancerConfig{
				Algorithm: LoadBalancerRoundRobin,
			},
			MaxSessions: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 500,
				QueueSize:     50,
				QueueTimeout:  Duration("10s"),
			},
			RateLimit: &RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
			Transform: &GRPCBackendTransformConfig{
				FieldMask: &GRPCFieldMaskConfig{
					Paths: []string{"user.id", "user.name"},
				},
				Metadata: &GRPCMetadataManipulation{
					Static: map[string]string{
						"x-source": "gateway",
					},
				},
			},
			Cache: &BackendCacheConfig{
				Enabled:       true,
				TTL:           Duration("10m"),
				KeyComponents: []string{"service", "method"},
				Type:          "memory",
			},
			Encoding: &BackendEncodingConfig{
				Request: &BackendEncodingSettings{
					ContentType: "application/grpc",
					Compression: "gzip",
				},
				Response: &BackendEncodingSettings{
					ContentType: "application/grpc",
					Compression: "gzip",
				},
			},
		},
		Status: GRPCBackendStatus{
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

	if backend.Name != "full-grpc-backend-new-fields" {
		t.Errorf("Name = %v, want full-grpc-backend-new-fields", backend.Name)
	}
	if backend.Spec.MaxSessions == nil {
		t.Error("Spec.MaxSessions should not be nil")
	}
	if backend.Spec.RateLimit == nil {
		t.Error("Spec.RateLimit should not be nil")
	}
	if backend.Spec.Transform == nil {
		t.Error("Spec.Transform should not be nil")
	}
	if backend.Spec.Cache == nil {
		t.Error("Spec.Cache should not be nil")
	}
	if backend.Spec.Encoding == nil {
		t.Error("Spec.Encoding should not be nil")
	}
}

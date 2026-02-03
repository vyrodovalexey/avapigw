// Package v1alpha1 contains API Schema definitions for the avapigw v1alpha1 API group.
package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBackend_TypeMeta(t *testing.T) {
	backend := &Backend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "Backend",
		},
	}

	if backend.APIVersion != "avapigw.io/v1alpha1" {
		t.Errorf("APIVersion = %v, want avapigw.io/v1alpha1", backend.APIVersion)
	}
	if backend.Kind != "Backend" {
		t.Errorf("Kind = %v, want Backend", backend.Kind)
	}
}

func TestBackend_ObjectMeta(t *testing.T) {
	backend := &Backend{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-backend",
			Namespace: "test-namespace",
		},
	}

	if backend.Name != "test-backend" {
		t.Errorf("Name = %v, want test-backend", backend.Name)
	}
	if backend.Namespace != "test-namespace" {
		t.Errorf("Namespace = %v, want test-namespace", backend.Namespace)
	}
}

func TestBackendSpec_Hosts(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{
			{
				Address: "10.0.1.10",
				Port:    8080,
				Weight:  1,
			},
			{
				Address: "10.0.1.11",
				Port:    8080,
				Weight:  2,
			},
		},
	}

	if len(spec.Hosts) != 2 {
		t.Fatalf("Hosts length = %v, want 2", len(spec.Hosts))
	}
	if spec.Hosts[0].Address != "10.0.1.10" {
		t.Errorf("Hosts[0].Address = %v, want 10.0.1.10", spec.Hosts[0].Address)
	}
	if spec.Hosts[0].Port != 8080 {
		t.Errorf("Hosts[0].Port = %v, want 8080", spec.Hosts[0].Port)
	}
	if spec.Hosts[0].Weight != 1 {
		t.Errorf("Hosts[0].Weight = %v, want 1", spec.Hosts[0].Weight)
	}
}

func TestBackendHost_AllFields(t *testing.T) {
	host := BackendHost{
		Address: "backend.example.com",
		Port:    443,
		Weight:  50,
	}

	if host.Address != "backend.example.com" {
		t.Errorf("Address = %v, want backend.example.com", host.Address)
	}
	if host.Port != 443 {
		t.Errorf("Port = %v, want 443", host.Port)
	}
	if host.Weight != 50 {
		t.Errorf("Weight = %v, want 50", host.Weight)
	}
}

func TestBackendSpec_HealthCheck(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		HealthCheck: &HealthCheckConfig{
			Path:               "/health",
			Interval:           Duration("10s"),
			Timeout:            Duration("5s"),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
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
	if spec.HealthCheck.HealthyThreshold != 2 {
		t.Errorf("HealthCheck.HealthyThreshold = %v, want 2", spec.HealthCheck.HealthyThreshold)
	}
	if spec.HealthCheck.UnhealthyThreshold != 3 {
		t.Errorf("HealthCheck.UnhealthyThreshold = %v, want 3", spec.HealthCheck.UnhealthyThreshold)
	}
}

func TestHealthCheckConfig_AllFields(t *testing.T) {
	hc := HealthCheckConfig{
		Path:               "/healthz",
		Interval:           Duration("15s"),
		Timeout:            Duration("3s"),
		HealthyThreshold:   3,
		UnhealthyThreshold: 5,
	}

	if hc.Path != "/healthz" {
		t.Errorf("Path = %v, want /healthz", hc.Path)
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

func TestBackendSpec_LoadBalancer(t *testing.T) {
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
			spec := BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
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

func TestBackendSpec_TLS(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		TLS: &BackendTLSConfig{
			Enabled:            true,
			Mode:               "MUTUAL",
			CAFile:             "/certs/ca.crt",
			CertFile:           "/certs/client.crt",
			KeyFile:            "/certs/client.key",
			ServerName:         "backend.internal",
			InsecureSkipVerify: false,
			MinVersion:         "TLS12",
			MaxVersion:         "TLS13",
			CipherSuites:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			ALPN:               []string{"h2", "http/1.1"},
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
	if spec.TLS.CAFile != "/certs/ca.crt" {
		t.Errorf("TLS.CAFile = %v, want /certs/ca.crt", spec.TLS.CAFile)
	}
	if spec.TLS.ServerName != "backend.internal" {
		t.Errorf("TLS.ServerName = %v, want backend.internal", spec.TLS.ServerName)
	}
	if spec.TLS.MinVersion != "TLS12" {
		t.Errorf("TLS.MinVersion = %v, want TLS12", spec.TLS.MinVersion)
	}
}

func TestBackendTLSConfig_Vault(t *testing.T) {
	tls := BackendTLSConfig{
		Enabled: true,
		Mode:    "MUTUAL",
		Vault: &VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "backend-client",
			CommonName: "gateway-client",
			AltNames:   []string{"gateway.local"},
			TTL:        "24h",
		},
	}

	if tls.Vault == nil {
		t.Fatal("Vault should not be nil")
	}
	if !tls.Vault.Enabled {
		t.Error("Vault.Enabled should be true")
	}
	if tls.Vault.PKIMount != "pki" {
		t.Errorf("Vault.PKIMount = %v, want pki", tls.Vault.PKIMount)
	}
	if tls.Vault.Role != "backend-client" {
		t.Errorf("Vault.Role = %v, want backend-client", tls.Vault.Role)
	}
	if tls.Vault.CommonName != "gateway-client" {
		t.Errorf("Vault.CommonName = %v, want gateway-client", tls.Vault.CommonName)
	}
	if tls.Vault.TTL != "24h" {
		t.Errorf("Vault.TTL = %v, want 24h", tls.Vault.TTL)
	}
}

func TestVaultBackendTLSConfig_AllFields(t *testing.T) {
	vtls := VaultBackendTLSConfig{
		Enabled:    true,
		PKIMount:   "pki",
		Role:       "client-cert",
		CommonName: "client.example.com",
		AltNames:   []string{"client2.example.com", "client3.example.com"},
		TTL:        "48h",
	}

	if !vtls.Enabled {
		t.Error("Enabled should be true")
	}
	if vtls.PKIMount != "pki" {
		t.Errorf("PKIMount = %v, want pki", vtls.PKIMount)
	}
	if vtls.Role != "client-cert" {
		t.Errorf("Role = %v, want client-cert", vtls.Role)
	}
	if vtls.CommonName != "client.example.com" {
		t.Errorf("CommonName = %v, want client.example.com", vtls.CommonName)
	}
	if len(vtls.AltNames) != 2 {
		t.Errorf("AltNames length = %v, want 2", len(vtls.AltNames))
	}
	if vtls.TTL != "48h" {
		t.Errorf("TTL = %v, want 48h", vtls.TTL)
	}
}

func TestBackendSpec_CircuitBreaker(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
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
	if spec.CircuitBreaker.HalfOpenRequests != 3 {
		t.Errorf("CircuitBreaker.HalfOpenRequests = %v, want 3", spec.CircuitBreaker.HalfOpenRequests)
	}
}

func TestBackendSpec_Authentication_JWT(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
			JWT: &BackendJWTAuthConfig{
				Enabled:      true,
				TokenSource:  "oidc",
				HeaderName:   "Authorization",
				HeaderPrefix: "Bearer",
				OIDC: &BackendOIDCConfig{
					IssuerURL:     "https://keycloak.example.com/realms/myrealm",
					ClientID:      "gateway-client",
					ClientSecret:  "secret",
					Scopes:        []string{"openid", "profile"},
					TokenCacheTTL: Duration("5m"),
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
	if spec.Authentication.JWT.TokenSource != "oidc" {
		t.Errorf("Authentication.JWT.TokenSource = %v, want oidc", spec.Authentication.JWT.TokenSource)
	}
	if spec.Authentication.JWT.OIDC == nil {
		t.Fatal("Authentication.JWT.OIDC should not be nil")
	}
	if spec.Authentication.JWT.OIDC.IssuerURL != "https://keycloak.example.com/realms/myrealm" {
		t.Errorf("Authentication.JWT.OIDC.IssuerURL = %v, want https://keycloak.example.com/realms/myrealm", spec.Authentication.JWT.OIDC.IssuerURL)
	}
}

func TestBackendJWTAuthConfig_StaticToken(t *testing.T) {
	jwt := BackendJWTAuthConfig{
		Enabled:      true,
		TokenSource:  "static",
		StaticToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		HeaderName:   "Authorization",
		HeaderPrefix: "Bearer",
	}

	if !jwt.Enabled {
		t.Error("Enabled should be true")
	}
	if jwt.TokenSource != "static" {
		t.Errorf("TokenSource = %v, want static", jwt.TokenSource)
	}
	if jwt.StaticToken == "" {
		t.Error("StaticToken should not be empty")
	}
}

func TestBackendJWTAuthConfig_VaultToken(t *testing.T) {
	jwt := BackendJWTAuthConfig{
		Enabled:     true,
		TokenSource: "vault",
		VaultPath:   "secret/data/jwt-token",
	}

	if jwt.TokenSource != "vault" {
		t.Errorf("TokenSource = %v, want vault", jwt.TokenSource)
	}
	if jwt.VaultPath != "secret/data/jwt-token" {
		t.Errorf("VaultPath = %v, want secret/data/jwt-token", jwt.VaultPath)
	}
}

func TestBackendOIDCConfig_AllFields(t *testing.T) {
	oidc := BackendOIDCConfig{
		IssuerURL:    "https://auth.example.com",
		ClientID:     "my-client",
		ClientSecret: "my-secret",
		ClientSecretRef: &SecretKeySelector{
			Name: "oidc-secret",
			Key:  "client-secret",
		},
		Scopes:        []string{"openid", "profile", "email"},
		TokenCacheTTL: Duration("10m"),
	}

	if oidc.IssuerURL != "https://auth.example.com" {
		t.Errorf("IssuerURL = %v, want https://auth.example.com", oidc.IssuerURL)
	}
	if oidc.ClientID != "my-client" {
		t.Errorf("ClientID = %v, want my-client", oidc.ClientID)
	}
	if oidc.ClientSecretRef == nil {
		t.Fatal("ClientSecretRef should not be nil")
	}
	if oidc.ClientSecretRef.Name != "oidc-secret" {
		t.Errorf("ClientSecretRef.Name = %v, want oidc-secret", oidc.ClientSecretRef.Name)
	}
	if len(oidc.Scopes) != 3 {
		t.Errorf("Scopes length = %v, want 3", len(oidc.Scopes))
	}
	if oidc.TokenCacheTTL != Duration("10m") {
		t.Errorf("TokenCacheTTL = %v, want 10m", oidc.TokenCacheTTL)
	}
}

func TestSecretKeySelector_AllFields(t *testing.T) {
	selector := SecretKeySelector{
		Name: "my-secret",
		Key:  "password",
	}

	if selector.Name != "my-secret" {
		t.Errorf("Name = %v, want my-secret", selector.Name)
	}
	if selector.Key != "password" {
		t.Errorf("Key = %v, want password", selector.Key)
	}
}

func TestBackendSpec_Authentication_Basic(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		Authentication: &BackendAuthConfig{
			Type: "basic",
			Basic: &BackendBasicAuthConfig{
				Enabled:     true,
				Username:    "admin",
				Password:    "secret",
				VaultPath:   "secret/data/backend-creds",
				UsernameKey: "username",
				PasswordKey: "password",
			},
		},
	}

	if spec.Authentication.Type != "basic" {
		t.Errorf("Authentication.Type = %v, want basic", spec.Authentication.Type)
	}
	if spec.Authentication.Basic == nil {
		t.Fatal("Authentication.Basic should not be nil")
	}
	if !spec.Authentication.Basic.Enabled {
		t.Error("Authentication.Basic.Enabled should be true")
	}
	if spec.Authentication.Basic.Username != "admin" {
		t.Errorf("Authentication.Basic.Username = %v, want admin", spec.Authentication.Basic.Username)
	}
}

func TestBackendBasicAuthConfig_AllFields(t *testing.T) {
	basic := BackendBasicAuthConfig{
		Enabled:     true,
		Username:    "user",
		Password:    "pass",
		VaultPath:   "secret/creds",
		UsernameKey: "user_key",
		PasswordKey: "pass_key",
	}

	if !basic.Enabled {
		t.Error("Enabled should be true")
	}
	if basic.Username != "user" {
		t.Errorf("Username = %v, want user", basic.Username)
	}
	if basic.Password != "pass" {
		t.Errorf("Password = %v, want pass", basic.Password)
	}
	if basic.VaultPath != "secret/creds" {
		t.Errorf("VaultPath = %v, want secret/creds", basic.VaultPath)
	}
	if basic.UsernameKey != "user_key" {
		t.Errorf("UsernameKey = %v, want user_key", basic.UsernameKey)
	}
	if basic.PasswordKey != "pass_key" {
		t.Errorf("PasswordKey = %v, want pass_key", basic.PasswordKey)
	}
}

func TestBackendSpec_Authentication_MTLS(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		Authentication: &BackendAuthConfig{
			Type: "mtls",
			MTLS: &BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/certs/client.crt",
				KeyFile:  "/certs/client.key",
				CAFile:   "/certs/ca.crt",
			},
		},
	}

	if spec.Authentication.Type != "mtls" {
		t.Errorf("Authentication.Type = %v, want mtls", spec.Authentication.Type)
	}
	if spec.Authentication.MTLS == nil {
		t.Fatal("Authentication.MTLS should not be nil")
	}
	if !spec.Authentication.MTLS.Enabled {
		t.Error("Authentication.MTLS.Enabled should be true")
	}
	if spec.Authentication.MTLS.CertFile != "/certs/client.crt" {
		t.Errorf("Authentication.MTLS.CertFile = %v, want /certs/client.crt", spec.Authentication.MTLS.CertFile)
	}
}

func TestBackendMTLSAuthConfig_Vault(t *testing.T) {
	mtls := BackendMTLSAuthConfig{
		Enabled: true,
		Vault: &VaultBackendTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "client-cert",
			CommonName: "gateway-client",
		},
	}

	if mtls.Vault == nil {
		t.Fatal("Vault should not be nil")
	}
	if !mtls.Vault.Enabled {
		t.Error("Vault.Enabled should be true")
	}
	if mtls.Vault.PKIMount != "pki" {
		t.Errorf("Vault.PKIMount = %v, want pki", mtls.Vault.PKIMount)
	}
}

func TestBackendSpec_MaxSessions(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 500,
			QueueSize:     50,
			QueueTimeout:  Duration("10s"),
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

func TestBackendSpec_RateLimit(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
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
	if spec.RateLimit.RequestsPerSecond != 100 {
		t.Errorf("RateLimit.RequestsPerSecond = %v, want 100", spec.RateLimit.RequestsPerSecond)
	}
}

func TestBackendStatus_Conditions(t *testing.T) {
	now := metav1.Now()
	status := BackendStatus{
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
	if status.Conditions[1].Type != ConditionHealthy {
		t.Errorf("Conditions[1].Type = %v, want Healthy", status.Conditions[1].Type)
	}
	if status.ObservedGeneration != 1 {
		t.Errorf("ObservedGeneration = %v, want 1", status.ObservedGeneration)
	}
	if status.HealthyHosts != 2 {
		t.Errorf("HealthyHosts = %v, want 2", status.HealthyHosts)
	}
	if status.TotalHosts != 2 {
		t.Errorf("TotalHosts = %v, want 2", status.TotalHosts)
	}
	if status.LastHealthCheck == nil {
		t.Error("LastHealthCheck should not be nil")
	}
}

func TestBackendList_Items(t *testing.T) {
	list := &BackendList{
		Items: []Backend{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backend-1",
					Namespace: "default",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "backend-2",
					Namespace: "default",
				},
			},
		},
	}

	if len(list.Items) != 2 {
		t.Fatalf("Items length = %v, want 2", len(list.Items))
	}
	if list.Items[0].Name != "backend-1" {
		t.Errorf("Items[0].Name = %v, want backend-1", list.Items[0].Name)
	}
}

func TestBackend_FullSpec(t *testing.T) {
	now := metav1.Now()
	backend := &Backend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "Backend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-backend",
			Namespace: "default",
		},
		Spec: BackendSpec{
			Hosts: []BackendHost{
				{
					Address: "10.0.1.10",
					Port:    8080,
					Weight:  50,
				},
				{
					Address: "10.0.1.11",
					Port:    8080,
					Weight:  50,
				},
			},
			HealthCheck: &HealthCheckConfig{
				Path:               "/health",
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
					Role:       "backend-client",
					CommonName: "gateway-client",
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
					OIDC: &BackendOIDCConfig{
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "gateway-client",
						ClientSecretRef: &SecretKeySelector{
							Name: "keycloak-secret",
							Key:  "client-secret",
						},
						Scopes:        []string{"openid", "profile"},
						TokenCacheTTL: Duration("5m"),
					},
					HeaderName:   "Authorization",
					HeaderPrefix: "Bearer",
				},
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
		},
		Status: BackendStatus{
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
			HealthyHosts:       2,
			TotalHosts:         2,
			LastHealthCheck:    &now,
		},
	}

	// Verify all fields are set correctly
	if backend.Name != "full-backend" {
		t.Errorf("Name = %v, want full-backend", backend.Name)
	}
	if len(backend.Spec.Hosts) != 2 {
		t.Errorf("Spec.Hosts length = %v, want 2", len(backend.Spec.Hosts))
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
	if len(backend.Status.Conditions) != 2 {
		t.Errorf("Status.Conditions length = %v, want 2", len(backend.Status.Conditions))
	}
	if backend.Status.HealthyHosts != 2 {
		t.Errorf("Status.HealthyHosts = %v, want 2", backend.Status.HealthyHosts)
	}
}

// Tests for Backend with RequestLimits configuration

func TestBackendSpec_RequestLimits(t *testing.T) {
	tests := []struct {
		name string
		spec BackendSpec
	}{
		{
			name: "body size limit only",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				RequestLimits: &RequestLimitsConfig{
					MaxBodySize: 10485760, // 10MB
				},
			},
		},
		{
			name: "header size limit only",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				RequestLimits: &RequestLimitsConfig{
					MaxHeaderSize: 1048576, // 1MB
				},
			},
		},
		{
			name: "both limits",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
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

func TestBackendSpec_RequestLimits_AllFields(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
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

// Tests for Backend with Transform configuration

func TestBackendSpec_Transform(t *testing.T) {
	tests := []struct {
		name string
		spec BackendSpec
	}{
		{
			name: "request transform only",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Transform: &BackendTransformConfig{
					Request: &BackendRequestTransform{
						Template: `{"wrapped": {{.Body}}}`,
						Headers: &HeaderOperation{
							Set: map[string]string{"X-Gateway": "avapigw"},
						},
					},
				},
			},
		},
		{
			name: "response transform only",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Transform: &BackendTransformConfig{
					Response: &BackendResponseTransform{
						AllowFields: []string{"id", "name"},
						DenyFields:  []string{"password"},
						FieldMappings: map[string]string{
							"user_id": "userId",
						},
					},
				},
			},
		},
		{
			name: "both transforms",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Transform: &BackendTransformConfig{
					Request: &BackendRequestTransform{
						Template: `{"data": {{.Body}}}`,
					},
					Response: &BackendResponseTransform{
						AllowFields: []string{"id", "name", "email"},
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

func TestBackendSpec_Transform_AllFields(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		Transform: &BackendTransformConfig{
			Request: &BackendRequestTransform{
				Template: `{"wrapped": {{.Body}}, "timestamp": "{{.Timestamp}}"}`,
				Headers: &HeaderOperation{
					Set:    map[string]string{"Content-Type": "application/json"},
					Add:    map[string]string{"X-Request-ID": "{{.RequestID}}"},
					Remove: []string{"X-Internal-Header"},
				},
			},
			Response: &BackendResponseTransform{
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
			},
		},
	}

	transform := spec.Transform
	if transform == nil {
		t.Fatal("Transform should not be nil")
	}
	if transform.Request == nil {
		t.Fatal("Transform.Request should not be nil")
	}
	if transform.Response == nil {
		t.Fatal("Transform.Response should not be nil")
	}
	if transform.Request.Template == "" {
		t.Error("Transform.Request.Template should not be empty")
	}
	if len(transform.Response.AllowFields) != 4 {
		t.Errorf("Transform.Response.AllowFields length = %v, want 4", len(transform.Response.AllowFields))
	}
	if len(transform.Response.FieldMappings) != 3 {
		t.Errorf("Transform.Response.FieldMappings length = %v, want 3", len(transform.Response.FieldMappings))
	}
}

// Tests for Backend with Cache configuration

func TestBackendSpec_Cache(t *testing.T) {
	tests := []struct {
		name string
		spec BackendSpec
	}{
		{
			name: "basic cache",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Cache: &BackendCacheConfig{
					Enabled: true,
					TTL:     Duration("5m"),
				},
			},
		},
		{
			name: "cache with key components",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Cache: &BackendCacheConfig{
					Enabled:       true,
					TTL:           Duration("10m"),
					KeyComponents: []string{"path", "query", "headers.Authorization"},
				},
			},
		},
		{
			name: "cache with stale while revalidate",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Cache: &BackendCacheConfig{
					Enabled:              true,
					TTL:                  Duration("5m"),
					StaleWhileRevalidate: Duration("1m"),
				},
			},
		},
		{
			name: "redis cache",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
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

func TestBackendSpec_Cache_AllFields(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		Cache: &BackendCacheConfig{
			Enabled:              true,
			TTL:                  Duration("10m"),
			KeyComponents:        []string{"path", "query", "headers.Authorization", "headers.Accept"},
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
	if len(cache.KeyComponents) != 4 {
		t.Errorf("Cache.KeyComponents length = %v, want 4", len(cache.KeyComponents))
	}
	if cache.StaleWhileRevalidate != Duration("2m") {
		t.Errorf("Cache.StaleWhileRevalidate = %v, want 2m", cache.StaleWhileRevalidate)
	}
	if cache.Type != "redis" {
		t.Errorf("Cache.Type = %v, want redis", cache.Type)
	}
}

// Tests for Backend with Encoding configuration

func TestBackendSpec_Encoding(t *testing.T) {
	tests := []struct {
		name string
		spec BackendSpec
	}{
		{
			name: "request encoding only",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Encoding: &BackendEncodingConfig{
					Request: &BackendEncodingSettings{
						ContentType: "application/json",
						Compression: "gzip",
					},
				},
			},
		},
		{
			name: "response encoding only",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Encoding: &BackendEncodingConfig{
					Response: &BackendEncodingSettings{
						ContentType: "application/json",
						Compression: "br",
					},
				},
			},
		},
		{
			name: "both encodings",
			spec: BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Encoding: &BackendEncodingConfig{
					Request: &BackendEncodingSettings{
						ContentType: "application/json",
						Compression: "gzip",
					},
					Response: &BackendEncodingSettings{
						ContentType: "application/json",
						Compression: "br",
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

func TestBackendSpec_Encoding_AllFields(t *testing.T) {
	spec := BackendSpec{
		Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
		Encoding: &BackendEncodingConfig{
			Request: &BackendEncodingSettings{
				ContentType: "application/json",
				Compression: "gzip",
			},
			Response: &BackendEncodingSettings{
				ContentType: "application/xml",
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
	if encoding.Request.ContentType != "application/json" {
		t.Errorf("Encoding.Request.ContentType = %v, want application/json", encoding.Request.ContentType)
	}
	if encoding.Request.Compression != "gzip" {
		t.Errorf("Encoding.Request.Compression = %v, want gzip", encoding.Request.Compression)
	}
	if encoding.Response.ContentType != "application/xml" {
		t.Errorf("Encoding.Response.ContentType = %v, want application/xml", encoding.Response.ContentType)
	}
	if encoding.Response.Compression != "deflate" {
		t.Errorf("Encoding.Response.Compression = %v, want deflate", encoding.Response.Compression)
	}
}

func TestBackendSpec_Encoding_CompressionTypes(t *testing.T) {
	compressions := []string{"gzip", "deflate", "br", "none"}

	for _, compression := range compressions {
		t.Run(compression, func(t *testing.T) {
			spec := BackendSpec{
				Hosts: []BackendHost{{Address: "localhost", Port: 8080}},
				Encoding: &BackendEncodingConfig{
					Request: &BackendEncodingSettings{
						Compression: compression,
					},
				},
			}
			if spec.Encoding.Request.Compression != compression {
				t.Errorf("Encoding.Request.Compression = %v, want %v", spec.Encoding.Request.Compression, compression)
			}
		})
	}
}

// Tests for Backend with all new fields combined

func TestBackend_FullSpecWithAllNewFields(t *testing.T) {
	now := metav1.Now()
	backend := &Backend{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "avapigw.io/v1alpha1",
			Kind:       "Backend",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "full-backend-new-fields",
			Namespace: "default",
		},
		Spec: BackendSpec{
			Hosts: []BackendHost{
				{
					Address: "10.0.1.10",
					Port:    8080,
					Weight:  50,
				},
				{
					Address: "10.0.1.11",
					Port:    8080,
					Weight:  50,
				},
			},
			HealthCheck: &HealthCheckConfig{
				Path:     "/health",
				Interval: Duration("10s"),
				Timeout:  Duration("5s"),
			},
			LoadBalancer: &LoadBalancerConfig{
				Algorithm: LoadBalancerRoundRobin,
			},
			RequestLimits: &RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
			},
			Transform: &BackendTransformConfig{
				Request: &BackendRequestTransform{
					Template: `{"wrapped": {{.Body}}}`,
					Headers: &HeaderOperation{
						Set: map[string]string{"X-Gateway": "avapigw"},
					},
				},
				Response: &BackendResponseTransform{
					AllowFields: []string{"id", "name", "email"},
					FieldMappings: map[string]string{
						"user_id": "userId",
					},
				},
			},
			Cache: &BackendCacheConfig{
				Enabled:              true,
				TTL:                  Duration("10m"),
				KeyComponents:        []string{"path", "query"},
				StaleWhileRevalidate: Duration("2m"),
				Type:                 "memory",
			},
			Encoding: &BackendEncodingConfig{
				Request: &BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "gzip",
				},
				Response: &BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "br",
				},
			},
		},
		Status: BackendStatus{
			Conditions: []Condition{
				{
					Type:               ConditionReady,
					Status:             metav1.ConditionTrue,
					Reason:             ReasonReconciled,
					LastTransitionTime: now,
				},
			},
			ObservedGeneration: 1,
			HealthyHosts:       2,
			TotalHosts:         2,
			LastHealthCheck:    &now,
		},
	}

	if backend.Name != "full-backend-new-fields" {
		t.Errorf("Name = %v, want full-backend-new-fields", backend.Name)
	}
	if backend.Spec.RequestLimits == nil {
		t.Error("Spec.RequestLimits should not be nil")
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

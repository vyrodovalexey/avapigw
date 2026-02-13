// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"testing"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
)

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name      string
		duration  string
		wantError bool
	}{
		{"empty string", "", false},
		{"valid seconds", "30s", false},
		{"valid minutes", "5m", false},
		{"valid hours", "1h", false},
		{"valid milliseconds", "100ms", false},
		{"valid microseconds", "100us", false},
		{"valid nanoseconds", "100ns", false},
		{"valid combined", "1h30m", false},
		{"valid decimal", "1.5s", false},
		{"invalid format", "invalid", true},
		{"missing unit", "30", true},
		{"invalid unit", "30x", true},
		{"negative value", "-30s", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDuration(tt.duration)
			if (err != nil) != tt.wantError {
				t.Errorf("validateDuration(%q) error = %v, wantError %v", tt.duration, err, tt.wantError)
			}
		})
	}
}

func TestValidateRateLimit(t *testing.T) {
	tests := []struct {
		name      string
		rateLimit *avapigwv1alpha1.RateLimitConfig
		wantError bool
	}{
		{
			name: "disabled rate limit",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "valid rate limit",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             200,
			},
			wantError: false,
		},
		{
			name: "zero requests per second",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 0,
				Burst:             100,
			},
			wantError: true,
		},
		{
			name: "zero burst",
			rateLimit: &avapigwv1alpha1.RateLimitConfig{
				Enabled:           true,
				RequestsPerSecond: 100,
				Burst:             0,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimit(tt.rateLimit)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRateLimit() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateCORS(t *testing.T) {
	tests := []struct {
		name      string
		cors      *avapigwv1alpha1.CORSConfig
		wantError bool
	}{
		{
			name: "valid CORS",
			cors: &avapigwv1alpha1.CORSConfig{
				AllowOrigins: []string{"https://example.com"},
				AllowMethods: []string{"GET", "POST", "PUT", "DELETE"},
				AllowHeaders: []string{"Content-Type", "Authorization"},
				MaxAge:       3600,
			},
			wantError: false,
		},
		{
			name: "valid CORS with lowercase methods",
			cors: &avapigwv1alpha1.CORSConfig{
				AllowMethods: []string{"get", "post"},
			},
			wantError: false,
		},
		{
			name: "invalid method",
			cors: &avapigwv1alpha1.CORSConfig{
				AllowMethods: []string{"INVALID"},
			},
			wantError: true,
		},
		{
			name: "negative max age",
			cors: &avapigwv1alpha1.CORSConfig{
				MaxAge: -1,
			},
			wantError: true,
		},
		{
			name: "zero max age",
			cors: &avapigwv1alpha1.CORSConfig{
				MaxAge: 0,
			},
			wantError: false,
		},
		{
			name: "all valid methods",
			cors: &avapigwv1alpha1.CORSConfig{
				AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCORS(tt.cors)
			if (err != nil) != tt.wantError {
				t.Errorf("validateCORS() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateMaxSessions(t *testing.T) {
	tests := []struct {
		name        string
		maxSessions *avapigwv1alpha1.MaxSessionsConfig
		wantError   bool
	}{
		{
			name: "disabled max sessions",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "valid max sessions",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueSize:     50,
				QueueTimeout:  avapigwv1alpha1.Duration("30s"),
			},
			wantError: false,
		},
		{
			name: "zero max concurrent",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 0,
			},
			wantError: true,
		},
		{
			name: "negative queue size",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueSize:     -1,
			},
			wantError: true,
		},
		{
			name: "invalid queue timeout",
			maxSessions: &avapigwv1alpha1.MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueTimeout:  avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMaxSessions(tt.maxSessions)
			if (err != nil) != tt.wantError {
				t.Errorf("validateMaxSessions() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateRouteTLS(t *testing.T) {
	tests := []struct {
		name      string
		tls       *avapigwv1alpha1.RouteTLSConfig
		wantError bool
	}{
		{
			name: "valid TLS",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				CertFile:   "/certs/tls.crt",
				KeyFile:    "/certs/tls.key",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
			wantError: false,
		},
		{
			name: "invalid min version",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				MinVersion: "TLS10",
			},
			wantError: true,
		},
		{
			name: "invalid max version",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				MaxVersion: "TLS10",
			},
			wantError: true,
		},
		{
			name: "version mismatch",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
			wantError: true,
		},
		{
			name: "client validation without CA",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: true,
					CAFile:  "",
				},
			},
			wantError: true,
		},
		{
			name: "valid client validation",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				ClientValidation: &avapigwv1alpha1.ClientValidationConfig{
					Enabled: true,
					CAFile:  "/certs/ca.crt",
				},
			},
			wantError: false,
		},
		{
			name: "vault enabled without PKI mount",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "role",
				},
			},
			wantError: true,
		},
		{
			name: "vault enabled without role",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "",
				},
			},
			wantError: true,
		},
		{
			name: "valid vault config",
			tls: &avapigwv1alpha1.RouteTLSConfig{
				Vault: &avapigwv1alpha1.VaultTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "role",
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteTLS(tt.tls)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRouteTLS() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateBackendTLS(t *testing.T) {
	tests := []struct {
		name      string
		tls       *avapigwv1alpha1.BackendTLSConfig
		wantError bool
	}{
		{
			name: "disabled TLS",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "valid SIMPLE mode",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "SIMPLE",
			},
			wantError: false,
		},
		{
			name: "valid MUTUAL mode with certs",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:  true,
				Mode:     "MUTUAL",
				CertFile: "/certs/tls.crt",
				KeyFile:  "/certs/tls.key",
			},
			wantError: false,
		},
		{
			name: "valid MUTUAL mode with vault",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "MUTUAL",
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "role",
				},
			},
			wantError: false,
		},
		{
			name: "invalid mode",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "INVALID",
			},
			wantError: true,
		},
		{
			name: "invalid min version",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				MinVersion: "TLS10",
			},
			wantError: true,
		},
		{
			name: "invalid max version",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				MaxVersion: "TLS10",
			},
			wantError: true,
		},
		{
			name: "version mismatch",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:    true,
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
			wantError: true,
		},
		{
			name: "MUTUAL mode without certs or vault",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Mode:    "MUTUAL",
			},
			wantError: true,
		},
		{
			name: "MUTUAL mode with cert but no key",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled:  true,
				Mode:     "MUTUAL",
				CertFile: "/certs/tls.crt",
			},
			wantError: true,
		},
		{
			name: "vault enabled without PKI mount",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "role",
				},
			},
			wantError: true,
		},
		{
			name: "vault enabled without role",
			tls: &avapigwv1alpha1.BackendTLSConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendTLS(tt.tls)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendTLS() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateCircuitBreaker(t *testing.T) {
	tests := []struct {
		name           string
		circuitBreaker *avapigwv1alpha1.CircuitBreakerConfig
		wantError      bool
	}{
		{
			name: "disabled circuit breaker",
			circuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "valid circuit breaker",
			circuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          avapigwv1alpha1.Duration("30s"),
				HalfOpenRequests: 3,
			},
			wantError: false,
		},
		{
			name: "zero threshold",
			circuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 0,
				Timeout:   avapigwv1alpha1.Duration("30s"),
			},
			wantError: true,
		},
		{
			name: "missing timeout",
			circuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   avapigwv1alpha1.Duration(""),
			},
			wantError: true,
		},
		{
			name: "invalid timeout",
			circuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:   true,
				Threshold: 5,
				Timeout:   avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "negative half open requests",
			circuitBreaker: &avapigwv1alpha1.CircuitBreakerConfig{
				Enabled:          true,
				Threshold:        5,
				Timeout:          avapigwv1alpha1.Duration("30s"),
				HalfOpenRequests: -1,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCircuitBreaker(tt.circuitBreaker)
			if (err != nil) != tt.wantError {
				t.Errorf("validateCircuitBreaker() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateLoadBalancer(t *testing.T) {
	tests := []struct {
		name         string
		loadBalancer *avapigwv1alpha1.LoadBalancerConfig
		wantError    bool
	}{
		{
			name: "roundRobin",
			loadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRoundRobin,
			},
			wantError: false,
		},
		{
			name: "weighted",
			loadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerWeighted,
			},
			wantError: false,
		},
		{
			name: "leastConn",
			loadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerLeastConn,
			},
			wantError: false,
		},
		{
			name: "random",
			loadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: avapigwv1alpha1.LoadBalancerRandom,
			},
			wantError: false,
		},
		{
			name: "empty algorithm",
			loadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: "",
			},
			wantError: false,
		},
		{
			name: "invalid algorithm",
			loadBalancer: &avapigwv1alpha1.LoadBalancerConfig{
				Algorithm: "invalid",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLoadBalancer(tt.loadBalancer)
			if (err != nil) != tt.wantError {
				t.Errorf("validateLoadBalancer() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateBackendHosts(t *testing.T) {
	tests := []struct {
		name      string
		hosts     []avapigwv1alpha1.BackendHost
		wantError bool
	}{
		{
			name:      "no hosts",
			hosts:     []avapigwv1alpha1.BackendHost{},
			wantError: true,
		},
		{
			name: "valid single host",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend", Port: 8080, Weight: 100},
			},
			wantError: false,
		},
		{
			name: "valid multiple hosts with weights",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend1", Port: 8080, Weight: 70},
				{Address: "backend2", Port: 8080, Weight: 30},
			},
			wantError: false,
		},
		{
			name: "valid multiple hosts without weights",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend1", Port: 8080, Weight: 0},
				{Address: "backend2", Port: 8080, Weight: 0},
			},
			wantError: false,
		},
		{
			name: "missing address",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "", Port: 8080},
			},
			wantError: true,
		},
		{
			name: "invalid port zero",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend", Port: 0},
			},
			wantError: true,
		},
		{
			name: "invalid port too high",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend", Port: 70000},
			},
			wantError: true,
		},
		{
			name: "invalid weight too high",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend", Port: 8080, Weight: 150},
			},
			wantError: true,
		},
		{
			name: "negative weight",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend", Port: 8080, Weight: -10},
			},
			wantError: true,
		},
		{
			name: "weight sum not 100",
			hosts: []avapigwv1alpha1.BackendHost{
				{Address: "backend1", Port: 8080, Weight: 30},
				{Address: "backend2", Port: 8080, Weight: 30},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendHosts(tt.hosts)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendHosts() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateHealthCheck(t *testing.T) {
	tests := []struct {
		name        string
		healthCheck *avapigwv1alpha1.HealthCheckConfig
		wantError   bool
	}{
		{
			name: "valid health check",
			healthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:               "/health",
				Interval:           avapigwv1alpha1.Duration("10s"),
				Timeout:            avapigwv1alpha1.Duration("5s"),
				HealthyThreshold:   3,
				UnhealthyThreshold: 3,
			},
			wantError: false,
		},
		{
			name: "missing path",
			healthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path: "",
			},
			wantError: true,
		},
		{
			name: "invalid interval",
			healthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:     "/health",
				Interval: avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "invalid timeout",
			healthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:    "/health",
				Timeout: avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "negative healthy threshold",
			healthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:             "/health",
				HealthyThreshold: -1,
			},
			wantError: true,
		},
		{
			name: "negative unhealthy threshold",
			healthCheck: &avapigwv1alpha1.HealthCheckConfig{
				Path:               "/health",
				UnhealthyThreshold: -1,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHealthCheck(tt.healthCheck)
			if (err != nil) != tt.wantError {
				t.Errorf("validateHealthCheck() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateGRPCHealthCheck(t *testing.T) {
	tests := []struct {
		name        string
		healthCheck *avapigwv1alpha1.GRPCHealthCheckConfig
		wantError   bool
	}{
		{
			name: "valid gRPC health check",
			healthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Service:            "grpc.health.v1.Health",
				Interval:           avapigwv1alpha1.Duration("10s"),
				Timeout:            avapigwv1alpha1.Duration("5s"),
				HealthyThreshold:   3,
				UnhealthyThreshold: 3,
			},
			wantError: false,
		},
		{
			name: "invalid interval",
			healthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Interval: avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "invalid timeout",
			healthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				Timeout: avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "negative healthy threshold",
			healthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				HealthyThreshold: -1,
			},
			wantError: true,
		},
		{
			name: "negative unhealthy threshold",
			healthCheck: &avapigwv1alpha1.GRPCHealthCheckConfig{
				UnhealthyThreshold: -1,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGRPCHealthCheck(tt.healthCheck)
			if (err != nil) != tt.wantError {
				t.Errorf("validateGRPCHealthCheck() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateBackendAuth(t *testing.T) {
	tests := []struct {
		name      string
		auth      *avapigwv1alpha1.BackendAuthConfig
		wantError bool
	}{
		{
			name: "invalid type",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "invalid",
			},
			wantError: true,
		},
		{
			name: "jwt without config",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT:  nil,
			},
			wantError: true,
		},
		{
			name: "basic without config",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type:  "basic",
				Basic: nil,
			},
			wantError: true,
		},
		{
			name: "mtls without config",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: nil,
			},
			wantError: true,
		},
		{
			name: "valid jwt static",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "static",
					StaticToken: "token",
				},
			},
			wantError: false,
		},
		{
			name: "valid jwt vault",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "vault",
					VaultPath:   "secret/jwt",
				},
			},
			wantError: false,
		},
		{
			name: "valid jwt oidc",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "jwt",
				JWT: &avapigwv1alpha1.BackendJWTAuthConfig{
					Enabled:     true,
					TokenSource: "oidc",
					OIDC: &avapigwv1alpha1.BackendOIDCConfig{
						IssuerURL: "https://issuer.example.com",
						ClientID:  "client-id",
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid basic static",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:  true,
					Username: "user",
					Password: "pass",
				},
			},
			wantError: false,
		},
		{
			name: "valid basic vault",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "basic",
				Basic: &avapigwv1alpha1.BackendBasicAuthConfig{
					Enabled:   true,
					VaultPath: "secret/basic",
				},
			},
			wantError: false,
		},
		{
			name: "valid mtls files",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled:  true,
					CertFile: "/certs/client.crt",
					KeyFile:  "/certs/client.key",
				},
			},
			wantError: false,
		},
		{
			name: "valid mtls vault",
			auth: &avapigwv1alpha1.BackendAuthConfig{
				Type: "mtls",
				MTLS: &avapigwv1alpha1.BackendMTLSAuthConfig{
					Enabled: true,
					Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
						Enabled:  true,
						PKIMount: "pki",
						Role:     "role",
					},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendAuth(tt.auth)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateJWTAuth(t *testing.T) {
	tests := []struct {
		name      string
		jwt       *avapigwv1alpha1.BackendJWTAuthConfig
		wantError bool
	}{
		{
			name: "disabled",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "invalid token source",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "invalid",
			},
			wantError: true,
		},
		{
			name: "static without token",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "",
			},
			wantError: true,
		},
		{
			name: "vault without path",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "vault",
				VaultPath:   "",
			},
			wantError: true,
		},
		{
			name: "oidc without config",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC:        nil,
			},
			wantError: true,
		},
		{
			name: "oidc without issuer URL",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					IssuerURL: "",
					ClientID:  "client-id",
				},
			},
			wantError: true,
		},
		{
			name: "oidc without client ID",
			jwt: &avapigwv1alpha1.BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "oidc",
				OIDC: &avapigwv1alpha1.BackendOIDCConfig{
					IssuerURL: "https://issuer.example.com",
					ClientID:  "",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateJWTAuth(tt.jwt)
			if (err != nil) != tt.wantError {
				t.Errorf("validateJWTAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateBasicAuth(t *testing.T) {
	tests := []struct {
		name      string
		basic     *avapigwv1alpha1.BackendBasicAuthConfig
		wantError bool
	}{
		{
			name: "disabled",
			basic: &avapigwv1alpha1.BackendBasicAuthConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "missing credentials",
			basic: &avapigwv1alpha1.BackendBasicAuthConfig{
				Enabled:   true,
				Username:  "",
				Password:  "",
				VaultPath: "",
			},
			wantError: true,
		},
		{
			name: "valid static credentials",
			basic: &avapigwv1alpha1.BackendBasicAuthConfig{
				Enabled:  true,
				Username: "user",
				Password: "pass",
			},
			wantError: false,
		},
		{
			name: "valid vault path",
			basic: &avapigwv1alpha1.BackendBasicAuthConfig{
				Enabled:   true,
				VaultPath: "secret/basic",
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBasicAuth(tt.basic)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBasicAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateMTLSAuth(t *testing.T) {
	tests := []struct {
		name      string
		mtls      *avapigwv1alpha1.BackendMTLSAuthConfig
		wantError bool
	}{
		{
			name: "disabled",
			mtls: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "missing certs and vault",
			mtls: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "",
				KeyFile:  "",
			},
			wantError: true,
		},
		{
			name: "valid file certs",
			mtls: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled:  true,
				CertFile: "/certs/client.crt",
				KeyFile:  "/certs/client.key",
			},
			wantError: false,
		},
		{
			name: "valid vault",
			mtls: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "role",
				},
			},
			wantError: false,
		},
		{
			name: "vault without PKI mount",
			mtls: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "",
					Role:     "role",
				},
			},
			wantError: true,
		},
		{
			name: "vault without role",
			mtls: &avapigwv1alpha1.BackendMTLSAuthConfig{
				Enabled: true,
				Vault: &avapigwv1alpha1.VaultBackendTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMTLSAuth(tt.mtls)
			if (err != nil) != tt.wantError {
				t.Errorf("validateMTLSAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRedisSentinelSpec

func TestValidateRedisSentinelSpec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		sentinel  *avapigwv1alpha1.RedisSentinelSpec
		fieldPath string
		wantError bool
		errSubstr string
	}{
		{
			name:      "nil sentinel",
			sentinel:  nil,
			fieldPath: "test.sentinel",
			wantError: false,
		},
		{
			name: "valid sentinel config",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379", "sentinel-1:26379", "sentinel-2:26379"},
				DB:            0,
			},
			fieldPath: "test.sentinel",
			wantError: false,
		},
		{
			name: "valid sentinel with all fields",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:       "mymaster",
				SentinelAddrs:    []string{"sentinel-0:26379"},
				SentinelPassword: "sentinelpass",
				Password:         "masterpass",
				DB:               5,
			},
			fieldPath: "cache.sentinel",
			wantError: false,
		},
		{
			name: "empty masterName",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
			fieldPath: "test.sentinel",
			wantError: true,
			errSubstr: "masterName is required",
		},
		{
			name: "no addresses",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{},
			},
			fieldPath: "test.sentinel",
			wantError: true,
			errSubstr: "sentinelAddrs must have at least one address",
		},
		{
			name: "nil addresses",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: nil,
			},
			fieldPath: "test.sentinel",
			wantError: true,
			errSubstr: "sentinelAddrs must have at least one address",
		},
		{
			name: "empty address in list",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379", "", "sentinel-2:26379"},
			},
			fieldPath: "test.sentinel",
			wantError: true,
			errSubstr: "sentinelAddrs[1] cannot be empty",
		},
		{
			name: "invalid DB negative",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
				DB:            -1,
			},
			fieldPath: "test.sentinel",
			wantError: true,
			errSubstr: "db must be between 0 and 15",
		},
		{
			name: "invalid DB too high",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
				DB:            16,
			},
			fieldPath: "test.sentinel",
			wantError: true,
			errSubstr: "db must be between 0 and 15",
		},
		{
			name: "DB at max boundary",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "mymaster",
				SentinelAddrs: []string{"sentinel-0:26379"},
				DB:            15,
			},
			fieldPath: "test.sentinel",
			wantError: false,
		},
		{
			name: "fieldPath prefix in error message",
			sentinel: &avapigwv1alpha1.RedisSentinelSpec{
				MasterName:    "",
				SentinelAddrs: []string{"sentinel-0:26379"},
			},
			fieldPath: "authorization.cache.sentinel",
			wantError: true,
			errSubstr: "authorization.cache.sentinel.masterName",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateRedisSentinelSpec(tt.sentinel, tt.fieldPath)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRedisSentinelSpec() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && tt.errSubstr != "" {
				if !contains(err.Error(), tt.errSubstr) {
					t.Errorf("validateRedisSentinelSpec() error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// Tests for validateBackendCache with sentinel

func TestValidateBackendCache_WithSentinel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cache     *avapigwv1alpha1.BackendCacheConfig
		wantError bool
		errSubstr string
	}{
		{
			name: "disabled cache with sentinel is ok",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: false,
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel-0:26379"},
				},
			},
			wantError: false,
		},
		{
			name: "valid redis cache with sentinel",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
				Type:    "redis",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel-0:26379", "sentinel-1:26379"},
					DB:            0,
				},
			},
			wantError: false,
		},
		{
			name: "sentinel with memory type should fail",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				Type:    "memory",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel-0:26379"},
				},
			},
			wantError: true,
			errSubstr: "sentinel is only valid when cache.type is 'redis'",
		},
		{
			name: "sentinel with empty type should fail",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				Type:    "",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel-0:26379"},
				},
			},
			wantError: true,
			errSubstr: "sentinel is only valid when cache.type is 'redis'",
		},
		{
			name: "sentinel with invalid sentinel config",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				Type:    "redis",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "",
					SentinelAddrs: []string{"sentinel-0:26379"},
				},
			},
			wantError: true,
			errSubstr: "masterName is required",
		},
		{
			name: "redis cache without sentinel is valid",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
				Type:    "redis",
			},
			wantError: false,
		},
		{
			name: "invalid TTL",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
				Type:    "redis",
			},
			wantError: true,
			errSubstr: "cache.ttl is invalid",
		},
		{
			name: "invalid cache type",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				Type:    "memcached",
			},
			wantError: true,
			errSubstr: "cache.type must be 'memory' or 'redis'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateBackendCache(tt.cache)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendCache() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && tt.errSubstr != "" {
				if !contains(err.Error(), tt.errSubstr) {
					t.Errorf("validateBackendCache() error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// Tests for validateAuthzCacheConfig with sentinel

func TestValidateAuthzCacheConfig_WithSentinel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cache     *avapigwv1alpha1.AuthzCacheConfig
		wantError bool
		errSubstr string
	}{
		{
			name: "valid redis authz cache with sentinel",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
				MaxSize: 1000,
				Type:    "redis",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel-0:26379"},
					DB:            0,
				},
			},
			wantError: false,
		},
		{
			name: "sentinel with memory type should fail",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				Type:    "memory",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{"sentinel-0:26379"},
				},
			},
			wantError: true,
			errSubstr: "sentinel is only valid when type is 'redis'",
		},
		{
			name: "sentinel with invalid sentinel config",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				Type:    "redis",
				Sentinel: &avapigwv1alpha1.RedisSentinelSpec{
					MasterName:    "mymaster",
					SentinelAddrs: []string{},
				},
			},
			wantError: true,
			errSubstr: "sentinelAddrs must have at least one address",
		},
		{
			name: "redis authz cache without sentinel is valid",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
				MaxSize: 1000,
				Type:    "redis",
			},
			wantError: false,
		},
		{
			name: "invalid TTL",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
			errSubstr: "authorization.cache.ttl is invalid",
		},
		{
			name: "negative maxSize",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				MaxSize: -1,
			},
			wantError: true,
			errSubstr: "authorization.cache.maxSize must be non-negative",
		},
		{
			name: "invalid cache type",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				Type:    "memcached",
			},
			wantError: true,
			errSubstr: "authorization.cache.type must be 'memory' or 'redis'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateAuthzCacheConfig(tt.cache)
			if (err != nil) != tt.wantError {
				t.Errorf("validateAuthzCacheConfig() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && tt.errSubstr != "" {
				if !contains(err.Error(), tt.errSubstr) {
					t.Errorf("validateAuthzCacheConfig() error = %q, want substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// contains checks if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Tests for validateAuthentication

func TestValidateAuthentication(t *testing.T) {
	tests := []struct {
		name      string
		auth      *avapigwv1alpha1.AuthenticationConfig
		wantError bool
	}{
		{
			name: "disabled authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled but no method configured",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
			},
			wantError: true,
		},
		{
			name: "enabled with allow anonymous",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled:        true,
				AllowAnonymous: true,
			},
			wantError: false,
		},
		{
			name: "valid JWT authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					JWKSURL: "https://issuer.example.com/.well-known/jwks.json",
				},
			},
			wantError: false,
		},
		{
			name: "valid API key authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
					Enabled: true,
					Header:  "X-API-Key",
				},
			},
			wantError: false,
		},
		{
			name: "valid mTLS authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS: &avapigwv1alpha1.MTLSAuthConfig{
					Enabled: true,
					CAFile:  "/certs/ca.crt",
				},
			},
			wantError: false,
		},
		{
			name: "valid OIDC authentication",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled: true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{
						{
							Name:      "keycloak",
							IssuerURL: "https://keycloak.example.com/realms/myrealm",
							ClientID:  "my-client",
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "JWT enabled but not configured properly",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					// Missing JWKS URL, secret, or public key
				},
			},
			wantError: true,
		},
		{
			name: "API key enabled but not configured properly",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
					Enabled: true,
					// Missing header and query
				},
			},
			wantError: true,
		},
		{
			name: "mTLS enabled but missing CA file",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				MTLS: &avapigwv1alpha1.MTLSAuthConfig{
					Enabled: true,
					// Missing CAFile
				},
			},
			wantError: true,
		},
		{
			name: "OIDC enabled but no providers",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				OIDC: &avapigwv1alpha1.OIDCAuthConfig{
					Enabled:   true,
					Providers: []avapigwv1alpha1.OIDCProviderConfig{},
				},
			},
			wantError: true,
		},
		{
			name: "multiple authentication methods",
			auth: &avapigwv1alpha1.AuthenticationConfig{
				Enabled: true,
				JWT: &avapigwv1alpha1.JWTAuthConfig{
					Enabled: true,
					JWKSURL: "https://issuer.example.com/.well-known/jwks.json",
				},
				APIKey: &avapigwv1alpha1.APIKeyAuthConfig{
					Enabled: true,
					Header:  "X-API-Key",
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthentication(tt.auth)
			if (err != nil) != tt.wantError {
				t.Errorf("validateAuthentication() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRouteJWTAuth

func TestValidateRouteJWTAuth(t *testing.T) {
	tests := []struct {
		name      string
		jwt       *avapigwv1alpha1.JWTAuthConfig
		wantError bool
	}{
		{
			name: "valid with JWKS URL",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled: true,
				JWKSURL: "https://issuer.example.com/.well-known/jwks.json",
			},
			wantError: false,
		},
		{
			name: "valid with secret",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled: true,
				Secret:  "my-secret-key",
			},
			wantError: false,
		},
		{
			name: "valid with public key",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				PublicKey: "-----BEGIN PUBLIC KEY-----\n...",
			},
			wantError: false,
		},
		{
			name: "missing all key sources",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled: true,
			},
			wantError: true,
		},
		{
			name: "valid algorithm HS256",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				Secret:    "my-secret",
				Algorithm: "HS256",
			},
			wantError: false,
		},
		{
			name: "valid algorithm RS256",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "RS256",
			},
			wantError: false,
		},
		{
			name: "valid algorithm ES256",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "ES256",
			},
			wantError: false,
		},
		{
			name: "invalid algorithm",
			jwt: &avapigwv1alpha1.JWTAuthConfig{
				Enabled:   true,
				JWKSURL:   "https://issuer.example.com/.well-known/jwks.json",
				Algorithm: "INVALID",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteJWTAuth(tt.jwt)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRouteJWTAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRouteAPIKeyAuth

func TestValidateRouteAPIKeyAuth(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    *avapigwv1alpha1.APIKeyAuthConfig
		wantError bool
	}{
		{
			name: "valid with header",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled: true,
				Header:  "X-API-Key",
			},
			wantError: false,
		},
		{
			name: "valid with query",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled: true,
				Query:   "api_key",
			},
			wantError: false,
		},
		{
			name: "valid with both header and query",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled: true,
				Header:  "X-API-Key",
				Query:   "api_key",
			},
			wantError: false,
		},
		{
			name: "missing header and query",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled: true,
			},
			wantError: true,
		},
		{
			name: "valid hash algorithm sha256",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled:       true,
				Header:        "X-API-Key",
				HashAlgorithm: "sha256",
			},
			wantError: false,
		},
		{
			name: "valid hash algorithm sha512",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled:       true,
				Header:        "X-API-Key",
				HashAlgorithm: "sha512",
			},
			wantError: false,
		},
		{
			name: "valid hash algorithm bcrypt",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled:       true,
				Header:        "X-API-Key",
				HashAlgorithm: "bcrypt",
			},
			wantError: false,
		},
		{
			name: "invalid hash algorithm",
			apiKey: &avapigwv1alpha1.APIKeyAuthConfig{
				Enabled:       true,
				Header:        "X-API-Key",
				HashAlgorithm: "md5",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteAPIKeyAuth(tt.apiKey)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRouteAPIKeyAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRouteMTLSAuth

func TestValidateRouteMTLSAuth(t *testing.T) {
	tests := []struct {
		name      string
		mtls      *avapigwv1alpha1.MTLSAuthConfig
		wantError bool
	}{
		{
			name: "valid with CA file",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled: true,
				CAFile:  "/certs/ca.crt",
			},
			wantError: false,
		},
		{
			name: "missing CA file",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled: true,
			},
			wantError: true,
		},
		{
			name: "valid extract identity cn",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "cn",
			},
			wantError: false,
		},
		{
			name: "valid extract identity san",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "san",
			},
			wantError: false,
		},
		{
			name: "valid extract identity ou",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "ou",
			},
			wantError: false,
		},
		{
			name: "invalid extract identity",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:         true,
				CAFile:          "/certs/ca.crt",
				ExtractIdentity: "invalid",
			},
			wantError: true,
		},
		{
			name: "with allowed CNs",
			mtls: &avapigwv1alpha1.MTLSAuthConfig{
				Enabled:    true,
				CAFile:     "/certs/ca.crt",
				AllowedCNs: []string{"client1", "client2"},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteMTLSAuth(tt.mtls)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRouteMTLSAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRouteOIDCAuth

func TestValidateRouteOIDCAuth(t *testing.T) {
	tests := []struct {
		name      string
		oidc      *avapigwv1alpha1.OIDCAuthConfig
		wantError bool
	}{
		{
			name: "valid with single provider",
			oidc: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:      "keycloak",
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "my-client",
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid with multiple providers",
			oidc: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:      "keycloak",
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "keycloak-client",
					},
					{
						Name:      "google",
						IssuerURL: "https://accounts.google.com",
						ClientID:  "google-client",
					},
				},
			},
			wantError: false,
		},
		{
			name: "no providers",
			oidc: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled:   true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{},
			},
			wantError: true,
		},
		{
			name: "provider missing name",
			oidc: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:      "",
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "my-client",
					},
				},
			},
			wantError: true,
		},
		{
			name: "provider missing issuer URL",
			oidc: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:      "keycloak",
						IssuerURL: "",
						ClientID:  "my-client",
					},
				},
			},
			wantError: true,
		},
		{
			name: "provider missing client ID",
			oidc: &avapigwv1alpha1.OIDCAuthConfig{
				Enabled: true,
				Providers: []avapigwv1alpha1.OIDCProviderConfig{
					{
						Name:      "keycloak",
						IssuerURL: "https://keycloak.example.com/realms/myrealm",
						ClientID:  "",
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRouteOIDCAuth(tt.oidc)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRouteOIDCAuth() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateAuthorization

func TestValidateAuthorization(t *testing.T) {
	tests := []struct {
		name      string
		authz     *avapigwv1alpha1.AuthorizationConfig
		wantError bool
	}{
		{
			name: "disabled authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "enabled but no method configured",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled: true,
			},
			wantError: true,
		},
		{
			name: "valid RBAC authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.RBACPolicyConfig{
						{
							Name:   "admin-policy",
							Roles:  []string{"admin"},
							Effect: "allow",
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid ABAC authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				ABAC: &avapigwv1alpha1.ABACConfig{
					Enabled: true,
					Policies: []avapigwv1alpha1.ABACPolicyConfig{
						{
							Name:       "owner-policy",
							Expression: "request.user == resource.owner",
							Effect:     "allow",
						},
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid external authorization",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "deny",
				External: &avapigwv1alpha1.ExternalAuthzConfig{
					Enabled: true,
					OPA: &avapigwv1alpha1.OPAAuthzConfig{
						URL: "http://opa:8181/v1/data/authz/allow",
					},
				},
			},
			wantError: false,
		},
		{
			name: "invalid default policy",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "invalid",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
				},
			},
			wantError: true,
		},
		{
			name: "valid default policy allow",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled:       true,
				DefaultPolicy: "allow",
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
				},
			},
			wantError: false,
		},
		{
			name: "with cache enabled",
			authz: &avapigwv1alpha1.AuthorizationConfig{
				Enabled: true,
				RBAC: &avapigwv1alpha1.RBACConfig{
					Enabled: true,
				},
				Cache: &avapigwv1alpha1.AuthzCacheConfig{
					Enabled: true,
					TTL:     avapigwv1alpha1.Duration("5m"),
					MaxSize: 1000,
					Type:    "memory",
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthorization(tt.authz)
			if (err != nil) != tt.wantError {
				t.Errorf("validateAuthorization() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRBACConfig

func TestValidateRBACConfig(t *testing.T) {
	tests := []struct {
		name      string
		rbac      *avapigwv1alpha1.RBACConfig
		wantError bool
	}{
		{
			name: "valid RBAC with policies",
			rbac: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:   "admin-policy",
						Roles:  []string{"admin"},
						Effect: "allow",
					},
				},
			},
			wantError: false,
		},
		{
			name: "policy missing name",
			rbac: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:   "",
						Roles:  []string{"admin"},
						Effect: "allow",
					},
				},
			},
			wantError: true,
		},
		{
			name: "invalid effect",
			rbac: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:   "policy",
						Roles:  []string{"admin"},
						Effect: "invalid",
					},
				},
			},
			wantError: true,
		},
		{
			name: "valid effect deny",
			rbac: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:   "deny-policy",
						Roles:  []string{"guest"},
						Effect: "deny",
					},
				},
			},
			wantError: false,
		},
		{
			name: "negative priority",
			rbac: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:     "policy",
						Roles:    []string{"admin"},
						Priority: -1,
					},
				},
			},
			wantError: true,
		},
		{
			name: "valid priority",
			rbac: &avapigwv1alpha1.RBACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.RBACPolicyConfig{
					{
						Name:     "policy",
						Roles:    []string{"admin"},
						Priority: 100,
					},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRBACConfig(tt.rbac)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRBACConfig() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateABACConfig

func TestValidateABACConfig(t *testing.T) {
	tests := []struct {
		name      string
		abac      *avapigwv1alpha1.ABACConfig
		wantError bool
	}{
		{
			name: "valid ABAC with policies",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "owner-policy",
						Expression: "request.user == resource.owner",
						Effect:     "allow",
					},
				},
			},
			wantError: false,
		},
		{
			name: "policy missing name",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "",
						Expression: "request.user == resource.owner",
						Effect:     "allow",
					},
				},
			},
			wantError: true,
		},
		{
			name: "policy missing expression",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "policy",
						Expression: "",
						Effect:     "allow",
					},
				},
			},
			wantError: true,
		},
		{
			name: "invalid effect",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "policy",
						Expression: "true",
						Effect:     "invalid",
					},
				},
			},
			wantError: true,
		},
		{
			name: "negative priority",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "policy",
						Expression: "true",
						Priority:   -1,
					},
				},
			},
			wantError: true,
		},
		{
			name: "invalid CEL expression syntax",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "policy",
						Expression: "request.user ==",
						Effect:     "allow",
					},
				},
			},
			wantError: true,
		},
		{
			name: "invalid CEL expression undefined variable",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "policy",
						Expression: "undefined_var == true",
						Effect:     "allow",
					},
				},
			},
			wantError: true,
		},
		{
			name: "valid complex CEL expression",
			abac: &avapigwv1alpha1.ABACConfig{
				Enabled: true,
				Policies: []avapigwv1alpha1.ABACPolicyConfig{
					{
						Name:       "complex-policy",
						Expression: "identity.roles.exists(r, r == 'admin') || request.user == resource.owner",
						Effect:     "allow",
					},
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateABACConfig(tt.abac)
			if (err != nil) != tt.wantError {
				t.Errorf("validateABACConfig() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateExternalAuthzConfig

func TestValidateExternalAuthzConfig(t *testing.T) {
	tests := []struct {
		name      string
		external  *avapigwv1alpha1.ExternalAuthzConfig
		wantError bool
	}{
		{
			name: "valid OPA config",
			external: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL: "http://opa:8181/v1/data/authz/allow",
				},
			},
			wantError: false,
		},
		{
			name: "missing OPA config",
			external: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
			},
			wantError: true,
		},
		{
			name: "OPA missing URL",
			external: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL: "",
				},
			},
			wantError: true,
		},
		{
			name: "valid with timeout",
			external: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL: "http://opa:8181/v1/data/authz/allow",
				},
				Timeout: avapigwv1alpha1.Duration("5s"),
			},
			wantError: false,
		},
		{
			name: "invalid timeout",
			external: &avapigwv1alpha1.ExternalAuthzConfig{
				Enabled: true,
				OPA: &avapigwv1alpha1.OPAAuthzConfig{
					URL: "http://opa:8181/v1/data/authz/allow",
				},
				Timeout: avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExternalAuthzConfig(tt.external)
			if (err != nil) != tt.wantError {
				t.Errorf("validateExternalAuthzConfig() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateAuthzCacheConfig

func TestValidateAuthzCacheConfig(t *testing.T) {
	tests := []struct {
		name      string
		cache     *avapigwv1alpha1.AuthzCacheConfig
		wantError bool
	}{
		{
			name: "valid memory cache",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
				MaxSize: 1000,
				Type:    "memory",
			},
			wantError: false,
		},
		{
			name: "valid redis cache",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("10m"),
				MaxSize: 10000,
				Type:    "redis",
			},
			wantError: false,
		},
		{
			name: "invalid TTL",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "negative max size",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				MaxSize: -1,
			},
			wantError: true,
		},
		{
			name: "invalid cache type",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				Type:    "invalid",
			},
			wantError: true,
		},
		{
			name: "empty type defaults to memory",
			cache: &avapigwv1alpha1.AuthzCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuthzCacheConfig(tt.cache)
			if (err != nil) != tt.wantError {
				t.Errorf("validateAuthzCacheConfig() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateBackendTransform

func TestValidateBackendTransform(t *testing.T) {
	tests := []struct {
		name      string
		transform *avapigwv1alpha1.BackendTransformConfig
		wantError bool
	}{
		{
			name: "valid request transform",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Request: &avapigwv1alpha1.BackendRequestTransform{
					Template: `{"wrapped": {{.Body}}}`,
				},
			},
			wantError: false,
		},
		{
			name: "valid response transform with allow fields",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					AllowFields: []string{"id", "name"},
				},
			},
			wantError: false,
		},
		{
			name: "valid response transform with deny fields",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					DenyFields: []string{"password", "secret"},
				},
			},
			wantError: false,
		},
		{
			name: "invalid - both allow and deny fields",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					AllowFields: []string{"id", "name"},
					DenyFields:  []string{"password"},
				},
			},
			wantError: true,
		},
		{
			name: "valid with field mappings",
			transform: &avapigwv1alpha1.BackendTransformConfig{
				Response: &avapigwv1alpha1.BackendResponseTransform{
					FieldMappings: map[string]string{
						"user_id": "userId",
					},
				},
			},
			wantError: false,
		},
		{
			name:      "nil transform",
			transform: &avapigwv1alpha1.BackendTransformConfig{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendTransform(tt.transform)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendTransform() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateBackendCache

func TestValidateBackendCache(t *testing.T) {
	tests := []struct {
		name      string
		cache     *avapigwv1alpha1.BackendCacheConfig
		wantError bool
	}{
		{
			name: "disabled cache",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: false,
			},
			wantError: false,
		},
		{
			name: "valid memory cache",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("5m"),
				Type:    "memory",
			},
			wantError: false,
		},
		{
			name: "valid redis cache",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("10m"),
				Type:    "redis",
			},
			wantError: false,
		},
		{
			name: "invalid TTL",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				TTL:     avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "invalid stale while revalidate",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:              true,
				TTL:                  avapigwv1alpha1.Duration("5m"),
				StaleWhileRevalidate: avapigwv1alpha1.Duration("invalid"),
			},
			wantError: true,
		},
		{
			name: "invalid cache type",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled: true,
				Type:    "invalid",
			},
			wantError: true,
		},
		{
			name: "valid with key components",
			cache: &avapigwv1alpha1.BackendCacheConfig{
				Enabled:       true,
				TTL:           avapigwv1alpha1.Duration("5m"),
				KeyComponents: []string{"path", "query"},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendCache(tt.cache)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendCache() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateBackendEncoding

func TestValidateBackendEncoding(t *testing.T) {
	tests := []struct {
		name      string
		encoding  *avapigwv1alpha1.BackendEncodingConfig
		wantError bool
	}{
		{
			name: "valid request encoding gzip",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "gzip",
				},
			},
			wantError: false,
		},
		{
			name: "valid request encoding deflate",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "deflate",
				},
			},
			wantError: false,
		},
		{
			name: "valid request encoding br",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "br",
				},
			},
			wantError: false,
		},
		{
			name: "valid request encoding none",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "none",
				},
			},
			wantError: false,
		},
		{
			name: "invalid request compression",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "invalid",
				},
			},
			wantError: true,
		},
		{
			name: "invalid response compression",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					Compression: "invalid",
				},
			},
			wantError: true,
		},
		{
			name: "valid both encodings",
			encoding: &avapigwv1alpha1.BackendEncodingConfig{
				Request: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "gzip",
				},
				Response: &avapigwv1alpha1.BackendEncodingSettings{
					ContentType: "application/json",
					Compression: "br",
				},
			},
			wantError: false,
		},
		{
			name:      "nil encoding",
			encoding:  &avapigwv1alpha1.BackendEncodingConfig{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBackendEncoding(tt.encoding)
			if (err != nil) != tt.wantError {
				t.Errorf("validateBackendEncoding() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateGRPCBackendTransform

func TestValidateGRPCBackendTransform(t *testing.T) {
	tests := []struct {
		name      string
		transform *avapigwv1alpha1.GRPCBackendTransformConfig
		wantError bool
	}{
		{
			name: "valid field mask",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
					Paths: []string{"user.id", "user.name"},
				},
			},
			wantError: false,
		},
		{
			name: "valid metadata static",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Static: map[string]string{
						"x-source": "gateway",
					},
				},
			},
			wantError: false,
		},
		{
			name: "valid metadata dynamic",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Dynamic: map[string]string{
						"x-request-id": "{{.RequestID}}",
					},
				},
			},
			wantError: false,
		},
		{
			name: "empty field mask path",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				FieldMask: &avapigwv1alpha1.GRPCFieldMaskConfig{
					Paths: []string{"user.id", ""},
				},
			},
			wantError: true,
		},
		{
			name: "empty static metadata key",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Static: map[string]string{
						"":         "value",
						"x-source": "gateway",
					},
				},
			},
			wantError: true,
		},
		{
			name: "empty dynamic metadata key",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{
				Metadata: &avapigwv1alpha1.GRPCMetadataManipulation{
					Dynamic: map[string]string{
						"": "{{.RequestID}}",
					},
				},
			},
			wantError: true,
		},
		{
			name:      "nil transform",
			transform: &avapigwv1alpha1.GRPCBackendTransformConfig{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGRPCBackendTransform(tt.transform)
			if (err != nil) != tt.wantError {
				t.Errorf("validateGRPCBackendTransform() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// Tests for validateRequestLimits

func TestValidateRequestLimits(t *testing.T) {
	tests := []struct {
		name      string
		limits    *avapigwv1alpha1.RequestLimitsConfig
		wantError bool
	}{
		{
			name: "valid body size",
			limits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize: 10485760,
			},
			wantError: false,
		},
		{
			name: "valid header size",
			limits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxHeaderSize: 1048576,
			},
			wantError: false,
		},
		{
			name: "valid both sizes",
			limits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize:   10485760,
				MaxHeaderSize: 1048576,
			},
			wantError: false,
		},
		{
			name: "negative body size",
			limits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize: -1,
			},
			wantError: true,
		},
		{
			name: "negative header size",
			limits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxHeaderSize: -1,
			},
			wantError: true,
		},
		{
			name: "zero sizes are valid",
			limits: &avapigwv1alpha1.RequestLimitsConfig{
				MaxBodySize:   0,
				MaxHeaderSize: 0,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequestLimits(tt.limits)
			if (err != nil) != tt.wantError {
				t.Errorf("validateRequestLimits() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

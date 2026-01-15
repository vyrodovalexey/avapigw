package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalConfig_Validate_ValidConfig(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
			Listeners: []ListenerConfig{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
				},
			},
		},
		Routes: []LocalRoute{
			{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "test-backend"},
				},
			},
		},
		Backends: []LocalBackend{
			{
				Name:     "test-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestLocalConfig_Validate_EmptyGatewayName(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "",
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway name is required")
}

func TestLocalConfig_Validate_DuplicateRouteNames(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		Routes: []LocalRoute{
			{
				Name: "duplicate-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "test-backend"},
				},
			},
			{
				Name: "duplicate-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api/v2",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "test-backend"},
				},
			},
		},
		Backends: []LocalBackend{
			{
				Name:     "test-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate route name")
}

func TestLocalConfig_Validate_UnknownBackendRef(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		Routes: []LocalRoute{
			{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "unknown-backend"},
				},
			},
		},
		Backends: []LocalBackend{
			{
				Name:     "test-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "references unknown backend")
}

func TestListenerConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		listener  ListenerConfig
		wantError string
	}{
		{
			name: "valid HTTP listener",
			listener: ListenerConfig{
				Name:     "http",
				Port:     8080,
				Protocol: "HTTP",
			},
			wantError: "",
		},
		{
			name: "valid HTTPS listener",
			listener: ListenerConfig{
				Name:     "https",
				Port:     8443,
				Protocol: "HTTPS",
				TLS: &ListenerTLSConfig{
					Mode: "terminate",
				},
			},
			wantError: "",
		},
		{
			name: "missing name",
			listener: ListenerConfig{
				Port:     8080,
				Protocol: "HTTP",
			},
			wantError: "listener name is required",
		},
		{
			name: "invalid port",
			listener: ListenerConfig{
				Name:     "http",
				Port:     0,
				Protocol: "HTTP",
			},
			wantError: "listener port must be between 1 and 65535",
		},
		{
			name: "invalid protocol",
			listener: ListenerConfig{
				Name:     "http",
				Port:     8080,
				Protocol: "INVALID",
			},
			wantError: "invalid listener protocol",
		},
		{
			name: "HTTPS without TLS config",
			listener: ListenerConfig{
				Name:     "https",
				Port:     8443,
				Protocol: "HTTPS",
			},
			wantError: "TLS configuration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.listener.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestLocalRoute_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		route     LocalRoute
		wantError string
	}{
		{
			name: "valid route",
			route: LocalRoute{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "backend"},
				},
			},
			wantError: "",
		},
		{
			name: "missing name",
			route: LocalRoute{
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "backend"},
				},
			},
			wantError: "route name is required",
		},
		{
			name: "missing backend refs",
			route: LocalRoute{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
			},
			wantError: "at least one backend reference is required",
		},
		{
			name: "invalid HTTP method",
			route: LocalRoute{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				Methods: []string{"INVALID"},
				BackendRefs: []BackendRefConfig{
					{Name: "backend"},
				},
			},
			wantError: "invalid HTTP method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.route.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestPathMatchConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		pathMatch PathMatchConfig
		wantError string
	}{
		{
			name: "valid exact match",
			pathMatch: PathMatchConfig{
				Type:  "Exact",
				Value: "/api/v1/users",
			},
			wantError: "",
		},
		{
			name: "valid prefix match",
			pathMatch: PathMatchConfig{
				Type:  "PathPrefix",
				Value: "/api",
			},
			wantError: "",
		},
		{
			name: "valid regex match",
			pathMatch: PathMatchConfig{
				Type:  "RegularExpression",
				Value: "^/api/v[0-9]+/.*",
			},
			wantError: "",
		},
		{
			name: "invalid type",
			pathMatch: PathMatchConfig{
				Type:  "Invalid",
				Value: "/api",
			},
			wantError: "invalid path match type",
		},
		{
			name: "empty value",
			pathMatch: PathMatchConfig{
				Type:  "PathPrefix",
				Value: "",
			},
			wantError: "path match value is required",
		},
		{
			name: "invalid regex",
			pathMatch: PathMatchConfig{
				Type:  "RegularExpression",
				Value: "[invalid",
			},
			wantError: "invalid regular expression",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.pathMatch.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestLocalBackend_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		backend   LocalBackend
		wantError string
	}{
		{
			name: "valid backend",
			backend: LocalBackend{
				Name:     "test-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			wantError: "",
		},
		{
			name: "missing name",
			backend: LocalBackend{
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			wantError: "backend name is required",
		},
		{
			name: "missing endpoints",
			backend: LocalBackend{
				Name:     "test-backend",
				Protocol: "HTTP",
			},
			wantError: "at least one endpoint is required",
		},
		{
			name: "invalid protocol",
			backend: LocalBackend{
				Name:     "test-backend",
				Protocol: "INVALID",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			wantError: "invalid backend protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.backend.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestEndpointConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		endpoint  EndpointConfig
		wantError string
	}{
		{
			name: "valid endpoint",
			endpoint: EndpointConfig{
				Address: "localhost",
				Port:    8080,
			},
			wantError: "",
		},
		{
			name: "valid endpoint with weight",
			endpoint: EndpointConfig{
				Address: "localhost",
				Port:    8080,
				Weight:  100,
			},
			wantError: "",
		},
		{
			name: "missing address",
			endpoint: EndpointConfig{
				Port: 8080,
			},
			wantError: "endpoint address is required",
		},
		{
			name: "invalid port",
			endpoint: EndpointConfig{
				Address: "localhost",
				Port:    0,
			},
			wantError: "endpoint port must be between 1 and 65535",
		},
		{
			name: "negative weight",
			endpoint: EndpointConfig{
				Address: "localhost",
				Port:    8080,
				Weight:  -1,
			},
			wantError: "endpoint weight must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.endpoint.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestLocalRateLimit_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rateLimit LocalRateLimit
		wantError string
	}{
		{
			name: "valid rate limit",
			rateLimit: LocalRateLimit{
				Name:      "test-rate-limit",
				Algorithm: "token_bucket",
				Requests:  100,
				Window:    time.Minute,
			},
			wantError: "",
		},
		{
			name: "missing name",
			rateLimit: LocalRateLimit{
				Algorithm: "token_bucket",
				Requests:  100,
				Window:    time.Minute,
			},
			wantError: "rate limit name is required",
		},
		{
			name: "invalid algorithm",
			rateLimit: LocalRateLimit{
				Name:      "test-rate-limit",
				Algorithm: "invalid",
				Requests:  100,
				Window:    time.Minute,
			},
			wantError: "invalid rate limit algorithm",
		},
		{
			name: "zero requests",
			rateLimit: LocalRateLimit{
				Name:      "test-rate-limit",
				Algorithm: "token_bucket",
				Requests:  0,
				Window:    time.Minute,
			},
			wantError: "rate limit requests must be positive",
		},
		{
			name: "zero window",
			rateLimit: LocalRateLimit{
				Name:      "test-rate-limit",
				Algorithm: "token_bucket",
				Requests:  100,
				Window:    0,
			},
			wantError: "rate limit window must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.rateLimit.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestLocalAuthPolicy_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		authPolicy LocalAuthPolicy
		wantError  string
	}{
		{
			name: "valid JWT auth policy",
			authPolicy: LocalAuthPolicy{
				Name: "jwt-auth",
				JWT: &JWTAuthConfig{
					Issuer: "https://auth.example.com",
				},
			},
			wantError: "",
		},
		{
			name: "valid API key auth policy",
			authPolicy: LocalAuthPolicy{
				Name: "apikey-auth",
				APIKey: &APIKeyAuthConfig{
					Header: "X-API-Key",
				},
			},
			wantError: "",
		},
		{
			name: "missing name",
			authPolicy: LocalAuthPolicy{
				JWT: &JWTAuthConfig{
					Issuer: "https://auth.example.com",
				},
			},
			wantError: "auth policy name is required",
		},
		{
			name: "no auth method configured",
			authPolicy: LocalAuthPolicy{
				Name: "empty-auth",
			},
			wantError: "at least one authentication method must be configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.authPolicy.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestHealthCheckConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		healthCheck HealthCheckConfig
		wantError   string
	}{
		{
			name: "valid HTTP health check",
			healthCheck: HealthCheckConfig{
				Interval:           10 * time.Second,
				Timeout:            5 * time.Second,
				UnhealthyThreshold: 3,
				HealthyThreshold:   2,
				HTTP: &HTTPHealthCheckConfig{
					Path: "/health",
				},
			},
			wantError: "",
		},
		{
			name: "valid TCP health check",
			healthCheck: HealthCheckConfig{
				Interval:           10 * time.Second,
				Timeout:            5 * time.Second,
				UnhealthyThreshold: 3,
				HealthyThreshold:   2,
				TCP:                &TCPHealthCheckConfig{},
			},
			wantError: "",
		},
		{
			name: "zero interval",
			healthCheck: HealthCheckConfig{
				Interval:           0,
				Timeout:            5 * time.Second,
				UnhealthyThreshold: 3,
				HealthyThreshold:   2,
				HTTP: &HTTPHealthCheckConfig{
					Path: "/health",
				},
			},
			wantError: "health check interval must be positive",
		},
		{
			name: "no health check type",
			healthCheck: HealthCheckConfig{
				Interval:           10 * time.Second,
				Timeout:            5 * time.Second,
				UnhealthyThreshold: 3,
				HealthyThreshold:   2,
			},
			wantError: "at least one health check type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.healthCheck.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestLoadBalancerConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		loadBalancer LoadBalancerConfig
		wantError    string
	}{
		{
			name: "valid round robin",
			loadBalancer: LoadBalancerConfig{
				Algorithm: "RoundRobin",
			},
			wantError: "",
		},
		{
			name: "valid consistent hash",
			loadBalancer: LoadBalancerConfig{
				Algorithm: "ConsistentHash",
				ConsistentHash: &ConsistentHashConfig{
					Header: "X-User-ID",
				},
			},
			wantError: "",
		},
		{
			name: "invalid algorithm",
			loadBalancer: LoadBalancerConfig{
				Algorithm: "Invalid",
			},
			wantError: "invalid load balancer algorithm",
		},
		{
			name: "consistent hash without config",
			loadBalancer: LoadBalancerConfig{
				Algorithm: "ConsistentHash",
			},
			wantError: "consistentHash configuration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.loadBalancer.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestListenerTLSConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		tlsConfig ListenerTLSConfig
		wantError string
	}{
		{
			name:      "empty config is valid",
			tlsConfig: ListenerTLSConfig{},
			wantError: "",
		},
		{
			name: "valid terminate mode",
			tlsConfig: ListenerTLSConfig{
				Mode: "terminate",
			},
			wantError: "",
		},
		{
			name: "valid passthrough mode",
			tlsConfig: ListenerTLSConfig{
				Mode: "passthrough",
			},
			wantError: "",
		},
		{
			name: "invalid mode",
			tlsConfig: ListenerTLSConfig{
				Mode: "invalid",
			},
			wantError: "invalid TLS mode",
		},
		{
			name: "valid TLS versions",
			tlsConfig: ListenerTLSConfig{
				MinVersion: "1.2",
				MaxVersion: "1.3",
			},
			wantError: "",
		},
		{
			name: "invalid min version",
			tlsConfig: ListenerTLSConfig{
				MinVersion: "1.0",
			},
			wantError: "invalid TLS min version",
		},
		{
			name: "invalid max version",
			tlsConfig: ListenerTLSConfig{
				MaxVersion: "1.1",
			},
			wantError: "invalid TLS max version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.tlsConfig.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestBackendRefConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		backendRef BackendRefConfig
		wantError  string
	}{
		{
			name: "valid backend ref",
			backendRef: BackendRefConfig{
				Name: "backend",
			},
			wantError: "",
		},
		{
			name: "valid with weight and port",
			backendRef: BackendRefConfig{
				Name:   "backend",
				Weight: 100,
				Port:   8080,
			},
			wantError: "",
		},
		{
			name: "missing name",
			backendRef: BackendRefConfig{
				Weight: 100,
			},
			wantError: "backend reference name is required",
		},
		{
			name: "negative weight",
			backendRef: BackendRefConfig{
				Name:   "backend",
				Weight: -1,
			},
			wantError: "backend weight must be non-negative",
		},
		{
			name: "invalid port",
			backendRef: BackendRefConfig{
				Name: "backend",
				Port: 70000,
			},
			wantError: "backend port must be between 1 and 65535",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.backendRef.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestFilterConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		filter    FilterConfig
		wantError string
	}{
		{
			name: "valid request header modifier",
			filter: FilterConfig{
				Type: "RequestHeaderModifier",
			},
			wantError: "",
		},
		{
			name: "valid response header modifier",
			filter: FilterConfig{
				Type: "ResponseHeaderModifier",
			},
			wantError: "",
		},
		{
			name: "valid URL rewrite",
			filter: FilterConfig{
				Type: "URLRewrite",
			},
			wantError: "",
		},
		{
			name: "valid request redirect",
			filter: FilterConfig{
				Type: "RequestRedirect",
			},
			wantError: "",
		},
		{
			name: "invalid filter type",
			filter: FilterConfig{
				Type: "Invalid",
			},
			wantError: "invalid filter type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.filter.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestRetryConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		retry     RetryConfig
		wantError string
	}{
		{
			name: "valid retry config",
			retry: RetryConfig{
				NumRetries:          3,
				PerTryTimeout:       5 * time.Second,
				BackoffBaseInterval: 100 * time.Millisecond,
				BackoffMaxInterval:  1 * time.Second,
			},
			wantError: "",
		},
		{
			name: "zero values are valid",
			retry: RetryConfig{
				NumRetries: 0,
			},
			wantError: "",
		},
		{
			name: "negative num retries",
			retry: RetryConfig{
				NumRetries: -1,
			},
			wantError: "numRetries must be non-negative",
		},
		{
			name: "negative per try timeout",
			retry: RetryConfig{
				NumRetries:    3,
				PerTryTimeout: -1 * time.Second,
			},
			wantError: "perTryTimeout must be non-negative",
		},
		{
			name: "negative backoff base interval",
			retry: RetryConfig{
				NumRetries:          3,
				BackoffBaseInterval: -1 * time.Millisecond,
			},
			wantError: "backoffBaseInterval must be non-negative",
		},
		{
			name: "negative backoff max interval",
			retry: RetryConfig{
				NumRetries:         3,
				BackoffMaxInterval: -1 * time.Second,
			},
			wantError: "backoffMaxInterval must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.retry.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestRateLimitKeyConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		key       RateLimitKeyConfig
		wantError string
	}{
		{
			name: "valid IP key",
			key: RateLimitKeyConfig{
				Type: "IP",
			},
			wantError: "",
		},
		{
			name: "valid Header key",
			key: RateLimitKeyConfig{
				Type:   "Header",
				Header: "X-User-ID",
			},
			wantError: "",
		},
		{
			name: "valid User key",
			key: RateLimitKeyConfig{
				Type:  "User",
				Claim: "sub",
			},
			wantError: "",
		},
		{
			name: "invalid key type",
			key: RateLimitKeyConfig{
				Type: "Invalid",
			},
			wantError: "invalid rate limit key type",
		},
		{
			name: "Header key without header name",
			key: RateLimitKeyConfig{
				Type: "Header",
			},
			wantError: "header name is required for Header key type",
		},
		{
			name: "User key without claim",
			key: RateLimitKeyConfig{
				Type: "User",
			},
			wantError: "claim name is required for User key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.key.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestJWTAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		jwt       JWTAuthConfig
		wantError string
	}{
		{
			name: "valid with issuer",
			jwt: JWTAuthConfig{
				Issuer: "https://auth.example.com",
			},
			wantError: "",
		},
		{
			name: "valid with JWKS URL",
			jwt: JWTAuthConfig{
				JWKSURL: "https://auth.example.com/.well-known/jwks.json",
			},
			wantError: "",
		},
		{
			name: "valid with both",
			jwt: JWTAuthConfig{
				Issuer:  "https://auth.example.com",
				JWKSURL: "https://auth.example.com/.well-known/jwks.json",
			},
			wantError: "",
		},
		{
			name:      "missing both issuer and JWKS URL",
			jwt:       JWTAuthConfig{},
			wantError: "either JWKS URL or issuer is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.jwt.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestAPIKeyAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		apiKey    APIKeyAuthConfig
		wantError string
	}{
		{
			name: "valid with header",
			apiKey: APIKeyAuthConfig{
				Header: "X-API-Key",
			},
			wantError: "",
		},
		{
			name: "valid with query",
			apiKey: APIKeyAuthConfig{
				Query: "api_key",
			},
			wantError: "",
		},
		{
			name: "valid with both",
			apiKey: APIKeyAuthConfig{
				Header: "X-API-Key",
				Query:  "api_key",
			},
			wantError: "",
		},
		{
			name:      "missing both header and query",
			apiKey:    APIKeyAuthConfig{},
			wantError: "either header or query parameter must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.apiKey.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestBasicAuthConfig_Validate(t *testing.T) {
	t.Parallel()

	// BasicAuth validation always returns nil
	cfg := &BasicAuthConfig{
		Realm: "test",
	}
	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestOAuth2AuthConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		oauth2    OAuth2AuthConfig
		wantError string
	}{
		{
			name: "valid with token endpoint",
			oauth2: OAuth2AuthConfig{
				TokenEndpoint: "https://auth.example.com/oauth/token",
			},
			wantError: "",
		},
		{
			name: "valid with introspection endpoint",
			oauth2: OAuth2AuthConfig{
				IntrospectionEndpoint: "https://auth.example.com/oauth/introspect",
			},
			wantError: "",
		},
		{
			name:      "missing both endpoints",
			oauth2:    OAuth2AuthConfig{},
			wantError: "either token endpoint or introspection endpoint is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.oauth2.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestGatewayConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		gateway   GatewayConfig
		wantError string
	}{
		{
			name: "valid gateway",
			gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
			},
			wantError: "",
		},
		{
			name: "missing name",
			gateway: GatewayConfig{
				Listeners: []ListenerConfig{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
			},
			wantError: "gateway name is required",
		},
		{
			name: "duplicate listener names",
			gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
					{Name: "http", Port: 8081, Protocol: "HTTP"},
				},
			},
			wantError: "duplicate listener name",
		},
		{
			name: "duplicate listener ports",
			gateway: GatewayConfig{
				Name: "test-gateway",
				Listeners: []ListenerConfig{
					{Name: "http1", Port: 8080, Protocol: "HTTP"},
					{Name: "http2", Port: 8080, Protocol: "HTTP"},
				},
			},
			wantError: "duplicate listener port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.gateway.Validate()
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
			}
		})
	}
}

func TestLocalConfig_Validate_DuplicateBackendNames(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		Backends: []LocalBackend{
			{
				Name:     "duplicate-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
			{
				Name:     "duplicate-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8081},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate backend name")
}

func TestLocalConfig_Validate_DuplicateRateLimitNames(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		RateLimits: []LocalRateLimit{
			{
				Name:      "duplicate-rate-limit",
				Algorithm: "token_bucket",
				Requests:  100,
				Window:    time.Minute,
			},
			{
				Name:      "duplicate-rate-limit",
				Algorithm: "token_bucket",
				Requests:  200,
				Window:    time.Minute,
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate rate limit name")
}

func TestLocalConfig_Validate_DuplicateAuthPolicyNames(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		AuthPolicies: []LocalAuthPolicy{
			{
				Name: "duplicate-auth",
				JWT: &JWTAuthConfig{
					Issuer: "https://auth.example.com",
				},
			},
			{
				Name: "duplicate-auth",
				JWT: &JWTAuthConfig{
					Issuer: "https://auth2.example.com",
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate auth policy name")
}

func TestLocalConfig_Validate_UnknownRateLimitRef(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		Routes: []LocalRoute{
			{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "test-backend"},
				},
				RateLimitRef: "unknown-rate-limit",
			},
		},
		Backends: []LocalBackend{
			{
				Name:     "test-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "references unknown rate limit")
}

func TestLocalConfig_Validate_UnknownAuthPolicyRef(t *testing.T) {
	t.Parallel()

	cfg := &LocalConfig{
		Gateway: GatewayConfig{
			Name: "test-gateway",
		},
		Routes: []LocalRoute{
			{
				Name: "test-route",
				PathMatch: PathMatchConfig{
					Type:  "PathPrefix",
					Value: "/api",
				},
				BackendRefs: []BackendRefConfig{
					{Name: "test-backend"},
				},
				AuthPolicyRef: "unknown-auth-policy",
			},
		},
		Backends: []LocalBackend{
			{
				Name:     "test-backend",
				Protocol: "HTTP",
				Endpoints: []EndpointConfig{
					{Address: "localhost", Port: 8080},
				},
			},
		},
	}

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "references unknown auth policy")
}

func TestLocalRoute_Validate_WithRetries(t *testing.T) {
	t.Parallel()

	route := LocalRoute{
		Name: "test-route",
		PathMatch: PathMatchConfig{
			Type:  "PathPrefix",
			Value: "/api",
		},
		BackendRefs: []BackendRefConfig{
			{Name: "backend"},
		},
		Retries: &RetryConfig{
			NumRetries: -1, // Invalid
		},
	}

	err := route.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retries validation failed")
}

func TestLocalBackend_Validate_WithLoadBalancer(t *testing.T) {
	t.Parallel()

	backend := LocalBackend{
		Name:     "test-backend",
		Protocol: "HTTP",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		LoadBalancer: &LoadBalancerConfig{
			Algorithm: "Invalid",
		},
	}

	err := backend.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loadBalancer validation failed")
}

func TestLocalBackend_Validate_WithHealthCheck(t *testing.T) {
	t.Parallel()

	backend := LocalBackend{
		Name:     "test-backend",
		Protocol: "HTTP",
		Endpoints: []EndpointConfig{
			{Address: "localhost", Port: 8080},
		},
		HealthCheck: &HealthCheckConfig{
			Interval: 0, // Invalid
		},
	}

	err := backend.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "healthCheck validation failed")
}

func TestLocalRateLimit_Validate_WithKey(t *testing.T) {
	t.Parallel()

	rateLimit := LocalRateLimit{
		Name:      "test-rate-limit",
		Algorithm: "token_bucket",
		Requests:  100,
		Window:    time.Minute,
		Key: &RateLimitKeyConfig{
			Type: "Invalid",
		},
	}

	err := rateLimit.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit key validation failed")
}

func TestLocalRateLimit_Validate_NegativeBurst(t *testing.T) {
	t.Parallel()

	rateLimit := LocalRateLimit{
		Name:      "test-rate-limit",
		Algorithm: "token_bucket",
		Requests:  100,
		Window:    time.Minute,
		Burst:     -1,
	}

	err := rateLimit.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limit burst must be non-negative")
}

func TestLocalAuthPolicy_Validate_WithInvalidJWT(t *testing.T) {
	t.Parallel()

	authPolicy := LocalAuthPolicy{
		Name: "test-auth",
		JWT:  &JWTAuthConfig{}, // Missing issuer and JWKS URL
	}

	err := authPolicy.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWT validation failed")
}

func TestLocalAuthPolicy_Validate_WithInvalidAPIKey(t *testing.T) {
	t.Parallel()

	authPolicy := LocalAuthPolicy{
		Name:   "test-auth",
		APIKey: &APIKeyAuthConfig{}, // Missing header and query
	}

	err := authPolicy.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "API key validation failed")
}

func TestLocalAuthPolicy_Validate_WithInvalidOAuth2(t *testing.T) {
	t.Parallel()

	authPolicy := LocalAuthPolicy{
		Name:   "test-auth",
		OAuth2: &OAuth2AuthConfig{}, // Missing endpoints
	}

	err := authPolicy.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OAuth2 validation failed")
}

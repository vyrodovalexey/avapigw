package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidationError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      ValidationError
		expected string
	}{
		{
			name:     "with path",
			err:      ValidationError{Path: "spec.listeners", Message: "required"},
			expected: "spec.listeners: required",
		},
		{
			name:     "without path",
			err:      ValidationError{Path: "", Message: "invalid config"},
			expected: "invalid config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestValidationErrors_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		errors   ValidationErrors
		contains []string
	}{
		{
			name:     "no errors",
			errors:   ValidationErrors{},
			contains: []string{"no validation errors"},
		},
		{
			name: "single error",
			errors: ValidationErrors{
				{Path: "spec.listeners", Message: "required"},
			},
			contains: []string{"spec.listeners: required"},
		},
		{
			name: "multiple errors",
			errors: ValidationErrors{
				{Path: "spec.listeners", Message: "required"},
				{Path: "metadata.name", Message: "required"},
			},
			contains: []string{"2 validation errors", "spec.listeners", "metadata.name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.errors.Error()
			for _, s := range tt.contains {
				assert.Contains(t, result, s)
			}
		})
	}
}

func TestValidationErrors_HasErrors(t *testing.T) {
	t.Parallel()

	assert.False(t, ValidationErrors{}.HasErrors())
	assert.True(t, ValidationErrors{{Path: "test", Message: "error"}}.HasErrors())
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	v := NewValidator()
	assert.NotNil(t, v)
	assert.Empty(t, v.errors)
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		t.Parallel()
		cfg := &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{Name: "http", Port: 8080, Protocol: "HTTP"},
				},
			},
		}
		err := ValidateConfig(cfg)
		assert.NoError(t, err)
	})

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()
		err := ValidateConfig(nil)
		assert.Error(t, err)
	})
}

func TestValidator_Validate_Root(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    *GatewayConfig
		wantErr   bool
		errFields []string
	}{
		{
			name: "missing apiVersion",
			config: &GatewayConfig{
				Kind:     "Gateway",
				Metadata: Metadata{Name: "test"},
				Spec:     GatewaySpec{Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}}},
			},
			wantErr:   true,
			errFields: []string{"apiVersion"},
		},
		{
			name: "invalid apiVersion prefix",
			config: &GatewayConfig{
				APIVersion: "invalid/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec:       GatewaySpec{Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}}},
			},
			wantErr:   true,
			errFields: []string{"apiVersion"},
		},
		{
			name: "missing kind",
			config: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Metadata:   Metadata{Name: "test"},
				Spec:       GatewaySpec{Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}}},
			},
			wantErr:   true,
			errFields: []string{"kind"},
		},
		{
			name: "invalid kind",
			config: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Invalid",
				Metadata:   Metadata{Name: "test"},
				Spec:       GatewaySpec{Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}}},
			},
			wantErr:   true,
			errFields: []string{"kind"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_Metadata(t *testing.T) {
	t.Parallel()

	cfg := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata:   Metadata{Name: ""},
		Spec:       GatewaySpec{Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}}},
	}

	err := ValidateConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "metadata.name")
}

func TestValidator_Validate_Listeners(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		listeners []Listener
		wantErr   bool
		errFields []string
	}{
		{
			name:      "no listeners",
			listeners: []Listener{},
			wantErr:   true,
			errFields: []string{"spec.listeners"},
		},
		{
			name: "missing listener name",
			listeners: []Listener{
				{Port: 8080, Protocol: "HTTP"},
			},
			wantErr:   true,
			errFields: []string{"name"},
		},
		{
			name: "duplicate listener name",
			listeners: []Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
				{Name: "http", Port: 8081, Protocol: "HTTP"},
			},
			wantErr:   true,
			errFields: []string{"duplicate"},
		},
		{
			name: "invalid port",
			listeners: []Listener{
				{Name: "http", Port: 0, Protocol: "HTTP"},
			},
			wantErr:   true,
			errFields: []string{"port"},
		},
		{
			name: "duplicate port",
			listeners: []Listener{
				{Name: "http1", Port: 8080, Protocol: "HTTP"},
				{Name: "http2", Port: 8080, Protocol: "HTTP"},
			},
			wantErr:   true,
			errFields: []string{"port"},
		},
		{
			name: "missing protocol",
			listeners: []Listener{
				{Name: "http", Port: 8080},
			},
			wantErr:   true,
			errFields: []string{"protocol"},
		},
		{
			name: "invalid protocol",
			listeners: []Listener{
				{Name: "http", Port: 8080, Protocol: "INVALID"},
			},
			wantErr:   true,
			errFields: []string{"protocol"},
		},
		{
			name: "valid protocols",
			listeners: []Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP"},
				{Name: "https", Port: 443, Protocol: "HTTPS"},
				{Name: "http2", Port: 8443, Protocol: "HTTP2"},
			},
			wantErr: false,
		},
		{
			name: "invalid bind address",
			listeners: []Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP", Bind: "invalid"},
			},
			wantErr:   true,
			errFields: []string{"bind"},
		},
		{
			name: "valid bind address",
			listeners: []Listener{
				{Name: "http", Port: 8080, Protocol: "HTTP", Bind: "0.0.0.0"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec:       GatewaySpec{Listeners: tt.listeners},
			}
			err := ValidateConfig(cfg)
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_Routes(t *testing.T) {
	t.Parallel()

	baseConfig := func(routes []Route) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Routes:    routes,
			},
		}
	}

	tests := []struct {
		name      string
		routes    []Route
		wantErr   bool
		errFields []string
	}{
		{
			name: "valid route",
			routes: []Route{
				{
					Name: "test-route",
					Match: []RouteMatch{
						{URI: &URIMatch{Prefix: "/api/"}},
					},
					Route: []RouteDestination{
						{Destination: Destination{Host: "backend", Port: 8080}},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing route name",
			routes: []Route{
				{
					Route: []RouteDestination{
						{Destination: Destination{Host: "backend", Port: 8080}},
					},
				},
			},
			wantErr:   true,
			errFields: []string{"name"},
		},
		{
			name: "duplicate route name",
			routes: []Route{
				{
					Name:  "test",
					Route: []RouteDestination{{Destination: Destination{Host: "backend", Port: 8080}}},
				},
				{
					Name:  "test",
					Route: []RouteDestination{{Destination: Destination{Host: "backend", Port: 8080}}},
				},
			},
			wantErr:   true,
			errFields: []string{"duplicate"},
		},
		{
			name: "no destination or redirect",
			routes: []Route{
				{Name: "test"},
			},
			wantErr:   true,
			errFields: []string{"destination"},
		},
		{
			name: "valid redirect",
			routes: []Route{
				{
					Name:     "redirect-route",
					Redirect: &RedirectConfig{URI: "/new-path", Code: 301},
				},
			},
			wantErr: false,
		},
		{
			name: "valid direct response",
			routes: []Route{
				{
					Name:           "direct-route",
					DirectResponse: &DirectResponseConfig{Status: 200, Body: "OK"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid weight sum",
			routes: []Route{
				{
					Name: "weighted-route",
					Route: []RouteDestination{
						{Destination: Destination{Host: "backend1", Port: 8080}, Weight: 30},
						{Destination: Destination{Host: "backend2", Port: 8080}, Weight: 30},
					},
				},
			},
			wantErr:   true,
			errFields: []string{"weight"},
		},
		{
			name: "valid weight sum",
			routes: []Route{
				{
					Name: "weighted-route",
					Route: []RouteDestination{
						{Destination: Destination{Host: "backend1", Port: 8080}, Weight: 50},
						{Destination: Destination{Host: "backend2", Port: 8080}, Weight: 50},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.routes))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_RouteMatch(t *testing.T) {
	t.Parallel()

	baseConfig := func(match RouteMatch) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Routes: []Route{
					{
						Name:  "test-route",
						Match: []RouteMatch{match},
						Route: []RouteDestination{{Destination: Destination{Host: "backend", Port: 8080}}},
					},
				},
			},
		}
	}

	tests := []struct {
		name      string
		match     RouteMatch
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid URI exact",
			match:   RouteMatch{URI: &URIMatch{Exact: "/api/v1"}},
			wantErr: false,
		},
		{
			name:    "valid URI prefix",
			match:   RouteMatch{URI: &URIMatch{Prefix: "/api/"}},
			wantErr: false,
		},
		{
			name:    "valid URI regex",
			match:   RouteMatch{URI: &URIMatch{Regex: "^/api/.*"}},
			wantErr: false,
		},
		{
			name:      "invalid URI regex",
			match:     RouteMatch{URI: &URIMatch{Regex: "[invalid"}},
			wantErr:   true,
			errFields: []string{"regex"},
		},
		{
			name:      "multiple URI types",
			match:     RouteMatch{URI: &URIMatch{Exact: "/api", Prefix: "/api/"}},
			wantErr:   true,
			errFields: []string{"only one"},
		},
		{
			name:    "valid methods",
			match:   RouteMatch{Methods: []string{"GET", "POST"}},
			wantErr: false,
		},
		{
			name:      "invalid method",
			match:     RouteMatch{Methods: []string{"INVALID"}},
			wantErr:   true,
			errFields: []string{"method"},
		},
		{
			name: "valid header match",
			match: RouteMatch{
				Headers: []HeaderMatch{{Name: "X-Custom", Exact: "value"}},
			},
			wantErr: false,
		},
		{
			name: "missing header name",
			match: RouteMatch{
				Headers: []HeaderMatch{{Exact: "value"}},
			},
			wantErr:   true,
			errFields: []string{"name"},
		},
		{
			name: "valid query param match",
			match: RouteMatch{
				QueryParams: []QueryParamMatch{{Name: "id", Exact: "123"}},
			},
			wantErr: false,
		},
		{
			name: "missing query param name",
			match: RouteMatch{
				QueryParams: []QueryParamMatch{{Exact: "123"}},
			},
			wantErr:   true,
			errFields: []string{"name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.match))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_Backends(t *testing.T) {
	t.Parallel()

	baseConfig := func(backends []Backend) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Backends:  backends,
			},
		}
	}

	tests := []struct {
		name      string
		backends  []Backend
		wantErr   bool
		errFields []string
	}{
		{
			name: "valid backend",
			backends: []Backend{
				{
					Name:  "user-service",
					Hosts: []BackendHost{{Address: "10.0.0.1", Port: 8080}},
				},
			},
			wantErr: false,
		},
		{
			name: "missing backend name",
			backends: []Backend{
				{Hosts: []BackendHost{{Address: "10.0.0.1", Port: 8080}}},
			},
			wantErr:   true,
			errFields: []string{"name"},
		},
		{
			name: "duplicate backend name",
			backends: []Backend{
				{Name: "service", Hosts: []BackendHost{{Address: "10.0.0.1", Port: 8080}}},
				{Name: "service", Hosts: []BackendHost{{Address: "10.0.0.2", Port: 8080}}},
			},
			wantErr:   true,
			errFields: []string{"duplicate"},
		},
		{
			name: "no hosts",
			backends: []Backend{
				{Name: "service", Hosts: []BackendHost{}},
			},
			wantErr:   true,
			errFields: []string{"host"},
		},
		{
			name: "missing host address",
			backends: []Backend{
				{Name: "service", Hosts: []BackendHost{{Port: 8080}}},
			},
			wantErr:   true,
			errFields: []string{"address"},
		},
		{
			name: "invalid host port",
			backends: []Backend{
				{Name: "service", Hosts: []BackendHost{{Address: "10.0.0.1", Port: 0}}},
			},
			wantErr:   true,
			errFields: []string{"port"},
		},
		{
			name: "negative weight",
			backends: []Backend{
				{Name: "service", Hosts: []BackendHost{{Address: "10.0.0.1", Port: 8080, Weight: -1}}},
			},
			wantErr:   true,
			errFields: []string{"weight"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.backends))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_HealthCheck(t *testing.T) {
	t.Parallel()

	baseConfig := func(hc *HealthCheck) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Backends: []Backend{
					{
						Name:        "service",
						Hosts:       []BackendHost{{Address: "10.0.0.1", Port: 8080}},
						HealthCheck: hc,
					},
				},
			},
		}
	}

	tests := []struct {
		name      string
		hc        *HealthCheck
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid health check",
			hc:      &HealthCheck{Path: "/health", Interval: Duration(10 * time.Second)},
			wantErr: false,
		},
		{
			name:      "missing path",
			hc:        &HealthCheck{Interval: Duration(10 * time.Second)},
			wantErr:   true,
			errFields: []string{"path"},
		},
		{
			name:      "negative interval",
			hc:        &HealthCheck{Path: "/health", Interval: Duration(-1 * time.Second)},
			wantErr:   true,
			errFields: []string{"interval"},
		},
		{
			name:      "negative timeout",
			hc:        &HealthCheck{Path: "/health", Timeout: Duration(-1 * time.Second)},
			wantErr:   true,
			errFields: []string{"timeout"},
		},
		{
			name:      "negative healthy threshold",
			hc:        &HealthCheck{Path: "/health", HealthyThreshold: -1},
			wantErr:   true,
			errFields: []string{"healthyThreshold"},
		},
		{
			name:      "negative unhealthy threshold",
			hc:        &HealthCheck{Path: "/health", UnhealthyThreshold: -1},
			wantErr:   true,
			errFields: []string{"unhealthyThreshold"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.hc))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_LoadBalancer(t *testing.T) {
	t.Parallel()

	baseConfig := func(lb *LoadBalancer) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Backends: []Backend{
					{
						Name:         "service",
						Hosts:        []BackendHost{{Address: "10.0.0.1", Port: 8080}},
						LoadBalancer: lb,
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		lb      *LoadBalancer
		wantErr bool
	}{
		{name: "roundRobin", lb: &LoadBalancer{Algorithm: "roundRobin"}, wantErr: false},
		{name: "weighted", lb: &LoadBalancer{Algorithm: "weighted"}, wantErr: false},
		{name: "leastConn", lb: &LoadBalancer{Algorithm: "leastConn"}, wantErr: false},
		{name: "random", lb: &LoadBalancer{Algorithm: "random"}, wantErr: false},
		{name: "empty", lb: &LoadBalancer{Algorithm: ""}, wantErr: false},
		{name: "invalid", lb: &LoadBalancer{Algorithm: "invalid"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.lb))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_RateLimit(t *testing.T) {
	t.Parallel()

	baseConfig := func(rl *RateLimitConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				RateLimit: rl,
			},
		}
	}

	tests := []struct {
		name      string
		rl        *RateLimitConfig
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid rate limit",
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 10},
			wantErr: false,
		},
		{
			name:    "disabled rate limit",
			rl:      &RateLimitConfig{Enabled: false},
			wantErr: false,
		},
		{
			name:      "zero requests per second when enabled",
			rl:        &RateLimitConfig{Enabled: true, RequestsPerSecond: 0},
			wantErr:   true,
			errFields: []string{"requestsPerSecond"},
		},
		{
			name:      "negative burst",
			rl:        &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: -1},
			wantErr:   true,
			errFields: []string{"burst"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.rl))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_CircuitBreaker(t *testing.T) {
	t.Parallel()

	baseConfig := func(cb *CircuitBreakerConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners:      []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				CircuitBreaker: cb,
			},
		}
	}

	tests := []struct {
		name      string
		cb        *CircuitBreakerConfig
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid circuit breaker",
			cb:      &CircuitBreakerConfig{Enabled: true, Threshold: 5, Timeout: Duration(30 * time.Second)},
			wantErr: false,
		},
		{
			name:    "disabled circuit breaker",
			cb:      &CircuitBreakerConfig{Enabled: false},
			wantErr: false,
		},
		{
			name:      "zero threshold when enabled",
			cb:        &CircuitBreakerConfig{Enabled: true, Threshold: 0, Timeout: Duration(30 * time.Second)},
			wantErr:   true,
			errFields: []string{"threshold"},
		},
		{
			name:      "zero timeout when enabled",
			cb:        &CircuitBreakerConfig{Enabled: true, Threshold: 5, Timeout: Duration(0)},
			wantErr:   true,
			errFields: []string{"timeout"},
		},
		{
			name:      "negative half open requests",
			cb:        &CircuitBreakerConfig{Enabled: true, Threshold: 5, Timeout: Duration(30 * time.Second), HalfOpenRequests: -1},
			wantErr:   true,
			errFields: []string{"halfOpenRequests"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.cb))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_CORS(t *testing.T) {
	t.Parallel()

	baseConfig := func(cors *CORSConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				CORS:      cors,
			},
		}
	}

	tests := []struct {
		name      string
		cors      *CORSConfig
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid CORS",
			cors:    &CORSConfig{AllowOrigins: []string{"*"}, AllowMethods: []string{"GET", "POST"}},
			wantErr: false,
		},
		{
			name:      "invalid method",
			cors:      &CORSConfig{AllowMethods: []string{"INVALID"}},
			wantErr:   true,
			errFields: []string{"method"},
		},
		{
			name:      "negative max age",
			cors:      &CORSConfig{MaxAge: -1},
			wantErr:   true,
			errFields: []string{"maxAge"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.cors))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_Observability(t *testing.T) {
	t.Parallel()

	baseConfig := func(obs *ObservabilityConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners:     []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Observability: obs,
			},
		}
	}

	tests := []struct {
		name      string
		obs       *ObservabilityConfig
		wantErr   bool
		errFields []string
	}{
		{
			name: "valid observability",
			obs: &ObservabilityConfig{
				Metrics: &MetricsConfig{Enabled: true, Path: "/metrics"},
				Tracing: &TracingConfig{Enabled: true, SamplingRate: 0.5},
				Logging: &LoggingConfig{Level: "info", Format: "json"},
			},
			wantErr: false,
		},
		{
			name:      "invalid metrics path",
			obs:       &ObservabilityConfig{Metrics: &MetricsConfig{Path: "metrics"}},
			wantErr:   true,
			errFields: []string{"path"},
		},
		{
			name:      "invalid metrics port",
			obs:       &ObservabilityConfig{Metrics: &MetricsConfig{Port: 70000}},
			wantErr:   true,
			errFields: []string{"port"},
		},
		{
			name:      "invalid sampling rate low",
			obs:       &ObservabilityConfig{Tracing: &TracingConfig{SamplingRate: -0.1}},
			wantErr:   true,
			errFields: []string{"samplingRate"},
		},
		{
			name:      "invalid sampling rate high",
			obs:       &ObservabilityConfig{Tracing: &TracingConfig{SamplingRate: 1.1}},
			wantErr:   true,
			errFields: []string{"samplingRate"},
		},
		{
			name:      "invalid log level",
			obs:       &ObservabilityConfig{Logging: &LoggingConfig{Level: "invalid"}},
			wantErr:   true,
			errFields: []string{"level"},
		},
		{
			name:      "invalid log format",
			obs:       &ObservabilityConfig{Logging: &LoggingConfig{Format: "invalid"}},
			wantErr:   true,
			errFields: []string{"format"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.obs))
			if tt.wantErr {
				require.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_Redirect(t *testing.T) {
	t.Parallel()

	baseConfig := func(redirect *RedirectConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Routes: []Route{
					{Name: "redirect-route", Redirect: redirect},
				},
			},
		}
	}

	tests := []struct {
		name      string
		redirect  *RedirectConfig
		wantErr   bool
		errFields []string
	}{
		{name: "valid 301", redirect: &RedirectConfig{Code: 301}, wantErr: false},
		{name: "valid 302", redirect: &RedirectConfig{Code: 302}, wantErr: false},
		{name: "valid 303", redirect: &RedirectConfig{Code: 303}, wantErr: false},
		{name: "valid 307", redirect: &RedirectConfig{Code: 307}, wantErr: false},
		{name: "valid 308", redirect: &RedirectConfig{Code: 308}, wantErr: false},
		{name: "default code", redirect: &RedirectConfig{Code: 0}, wantErr: false},
		{name: "invalid code", redirect: &RedirectConfig{Code: 200}, wantErr: true, errFields: []string{"code"}},
		{name: "invalid scheme", redirect: &RedirectConfig{Scheme: "ftp"}, wantErr: true, errFields: []string{"scheme"}},
		{name: "valid http scheme", redirect: &RedirectConfig{Scheme: "http"}, wantErr: false},
		{name: "valid https scheme", redirect: &RedirectConfig{Scheme: "https"}, wantErr: false},
		{name: "invalid port", redirect: &RedirectConfig{Port: 70000}, wantErr: true, errFields: []string{"port"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.redirect))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_DirectResponse(t *testing.T) {
	t.Parallel()

	baseConfig := func(dr *DirectResponseConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Routes: []Route{
					{Name: "direct-route", DirectResponse: dr},
				},
			},
		}
	}

	tests := []struct {
		name      string
		dr        *DirectResponseConfig
		wantErr   bool
		errFields []string
	}{
		{name: "valid 200", dr: &DirectResponseConfig{Status: 200}, wantErr: false},
		{name: "valid 404", dr: &DirectResponseConfig{Status: 404}, wantErr: false},
		{name: "invalid status low", dr: &DirectResponseConfig{Status: 99}, wantErr: true, errFields: []string{"status"}},
		{name: "invalid status high", dr: &DirectResponseConfig{Status: 600}, wantErr: true, errFields: []string{"status"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.dr))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_RetryPolicy(t *testing.T) {
	t.Parallel()

	baseConfig := func(retry *RetryPolicy) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Routes: []Route{
					{
						Name:    "retry-route",
						Retries: retry,
						Route:   []RouteDestination{{Destination: Destination{Host: "backend", Port: 8080}}},
					},
				},
			},
		}
	}

	tests := []struct {
		name      string
		retry     *RetryPolicy
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid retry",
			retry:   &RetryPolicy{Attempts: 3, PerTryTimeout: Duration(10 * time.Second)},
			wantErr: false,
		},
		{
			name:      "negative attempts",
			retry:     &RetryPolicy{Attempts: -1},
			wantErr:   true,
			errFields: []string{"attempts"},
		},
		{
			name:      "negative per try timeout",
			retry:     &RetryPolicy{Attempts: 3, PerTryTimeout: Duration(-1 * time.Second)},
			wantErr:   true,
			errFields: []string{"perTryTimeout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.retry))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_MaxSessions(t *testing.T) {
	t.Parallel()

	baseConfig := func(ms *MaxSessionsConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners:   []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				MaxSessions: ms,
			},
		}
	}

	tests := []struct {
		name      string
		ms        *MaxSessionsConfig
		wantErr   bool
		errFields []string
	}{
		{
			name:    "valid max sessions",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100},
			wantErr: false,
		},
		{
			name:    "disabled max sessions",
			ms:      &MaxSessionsConfig{Enabled: false},
			wantErr: false,
		},
		{
			name:    "valid with queue",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100, QueueSize: 50, QueueTimeout: Duration(30 * time.Second)},
			wantErr: false,
		},
		{
			name:      "zero max concurrent when enabled",
			ms:        &MaxSessionsConfig{Enabled: true, MaxConcurrent: 0},
			wantErr:   true,
			errFields: []string{"maxConcurrent"},
		},
		{
			name:      "negative max concurrent when enabled",
			ms:        &MaxSessionsConfig{Enabled: true, MaxConcurrent: -1},
			wantErr:   true,
			errFields: []string{"maxConcurrent"},
		},
		{
			name:      "negative queue size",
			ms:        &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100, QueueSize: -1},
			wantErr:   true,
			errFields: []string{"queueSize"},
		},
		{
			name:      "queue size without timeout",
			ms:        &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100, QueueSize: 10, QueueTimeout: 0},
			wantErr:   true,
			errFields: []string{"queueTimeout"},
		},
		{
			name:      "negative queue timeout",
			ms:        &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100, QueueTimeout: Duration(-1 * time.Second)},
			wantErr:   true,
			errFields: []string{"queueTimeout"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.ms))
			if tt.wantErr {
				assert.Error(t, err)
				for _, field := range tt.errFields {
					assert.Contains(t, err.Error(), field)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_RouteMaxSessions(t *testing.T) {
	t.Parallel()

	baseConfig := func(ms *MaxSessionsConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Routes: []Route{
					{
						Name:        "test-route",
						Match:       []RouteMatch{{URI: &URIMatch{Prefix: "/"}}},
						Route:       []RouteDestination{{Destination: Destination{Host: "backend", Port: 8080}}},
						MaxSessions: ms,
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		ms      *MaxSessionsConfig
		wantErr bool
	}{
		{
			name:    "valid route max sessions",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 50},
			wantErr: false,
		},
		{
			name:    "invalid route max sessions",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.ms))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_Validate_BackendMaxSessionsAndRateLimit(t *testing.T) {
	t.Parallel()

	baseConfig := func(ms *MaxSessionsConfig, rl *RateLimitConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test"},
			Spec: GatewaySpec{
				Listeners: []Listener{{Name: "http", Port: 8080, Protocol: "HTTP"}},
				Backends: []Backend{
					{
						Name:        "test-backend",
						Hosts:       []BackendHost{{Address: "10.0.0.1", Port: 8080}},
						MaxSessions: ms,
						RateLimit:   rl,
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		ms      *MaxSessionsConfig
		rl      *RateLimitConfig
		wantErr bool
	}{
		{
			name:    "valid backend max sessions",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100},
			rl:      nil,
			wantErr: false,
		},
		{
			name:    "valid backend rate limit",
			ms:      nil,
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 50},
			wantErr: false,
		},
		{
			name:    "valid both",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 100},
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 50},
			wantErr: false,
		},
		{
			name:    "invalid backend max sessions",
			ms:      &MaxSessionsConfig{Enabled: true, MaxConcurrent: 0},
			rl:      nil,
			wantErr: true,
		},
		{
			name:    "invalid backend rate limit",
			ms:      nil,
			rl:      &RateLimitConfig{Enabled: true, RequestsPerSecond: 0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.ms, tt.rl))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRouteTLSConfig(t *testing.T) {
	t.Parallel()

	baseConfig := func(routeTLS *RouteTLSConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test-gateway"},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{
						Name:     "https",
						Port:     8443,
						Protocol: "HTTPS",
						TLS: &ListenerTLSConfig{
							Mode:     "SIMPLE",
							CertFile: "/path/to/cert.pem",
							KeyFile:  "/path/to/key.pem",
						},
					},
				},
				Routes: []Route{
					{
						Name: "test-route",
						Match: []RouteMatch{
							{URI: &URIMatch{Prefix: "/api"}},
						},
						Route: []RouteDestination{
							{Destination: Destination{Host: "backend", Port: 8080}},
						},
						TLS: routeTLS,
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		tls     *RouteTLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil TLS config",
			tls:     nil,
			wantErr: false,
		},
		{
			name: "valid TLS with cert and key files",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
			},
			wantErr: false,
		},
		{
			name: "missing key file",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				SNIHosts: []string{"api.example.com"},
			},
			wantErr: true,
			errMsg:  "keyFile is required",
		},
		{
			name: "missing cert file",
			tls: &RouteTLSConfig{
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"api.example.com"},
			},
			wantErr: true,
			errMsg:  "certFile is required",
		},
		{
			name: "SNI hosts without certificate source",
			tls: &RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
			},
			wantErr: true,
			errMsg:  "certificate source",
		},
		{
			name: "invalid SNI host",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"invalid..hostname"},
			},
			wantErr: true,
			errMsg:  "sniHosts",
		},
		{
			name: "valid wildcard SNI host",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"*.example.com"},
			},
			wantErr: false,
		},
		{
			name: "invalid min TLS version",
			tls: &RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid TLS version",
		},
		{
			name: "invalid max TLS version",
			tls: &RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MaxVersion: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid TLS version",
		},
		{
			name: "min version greater than max version",
			tls: &RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: "TLS13",
				MaxVersion: "TLS12",
			},
			wantErr: true,
			errMsg:  "minVersion",
		},
		{
			name: "valid TLS versions",
			tls: &RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: "TLS12",
				MaxVersion: "TLS13",
			},
			wantErr: false,
		},
		{
			name: "valid Vault config",
			tls: &RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
				Vault: &VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "my-role",
					CommonName: "api.example.com",
				},
			},
			wantErr: false,
		},
		{
			name: "Vault missing pkiMount",
			tls: &RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
				Vault: &VaultTLSConfig{
					Enabled:    true,
					Role:       "my-role",
					CommonName: "api.example.com",
				},
			},
			wantErr: true,
			errMsg:  "pkiMount is required",
		},
		{
			name: "Vault missing role",
			tls: &RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
				Vault: &VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					CommonName: "api.example.com",
				},
			},
			wantErr: true,
			errMsg:  "role is required",
		},
		{
			name: "Vault missing commonName",
			tls: &RouteTLSConfig{
				SNIHosts: []string{"api.example.com"},
				Vault: &VaultTLSConfig{
					Enabled:  true,
					PKIMount: "pki",
					Role:     "my-role",
				},
			},
			wantErr: true,
			errMsg:  "commonName is required",
		},
		{
			name: "Vault disabled - no validation",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				Vault: &VaultTLSConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "client validation enabled without CA file",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				ClientValidation: &RouteClientValidationConfig{
					Enabled: true,
				},
			},
			wantErr: true,
			errMsg:  "caFile is required",
		},
		{
			name: "valid client validation config",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				ClientValidation: &RouteClientValidationConfig{
					Enabled: true,
					CAFile:  "/path/to/ca.pem",
				},
			},
			wantErr: false,
		},
		{
			name: "client validation disabled - no validation",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				ClientValidation: &RouteClientValidationConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.tls))
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateGRPCRouteTLSConfig(t *testing.T) {
	t.Parallel()

	baseConfig := func(routeTLS *RouteTLSConfig) *GatewayConfig {
		return &GatewayConfig{
			APIVersion: "gateway.avapigw.io/v1",
			Kind:       "Gateway",
			Metadata:   Metadata{Name: "test-gateway"},
			Spec: GatewaySpec{
				Listeners: []Listener{
					{
						Name:     "grpc",
						Port:     9443,
						Protocol: "GRPC",
						TLS: &ListenerTLSConfig{
							Mode:     "SIMPLE",
							CertFile: "/path/to/cert.pem",
							KeyFile:  "/path/to/key.pem",
						},
						GRPC: &GRPCListenerConfig{
							MaxConcurrentStreams: 100,
						},
					},
				},
				GRPCRoutes: []GRPCRoute{
					{
						Name: "test-grpc-route",
						Match: []GRPCRouteMatch{
							{Service: &StringMatch{Prefix: "test."}},
						},
						Route: []RouteDestination{
							{Destination: Destination{Host: "backend", Port: 9090}},
						},
						TLS: routeTLS,
					},
				},
			},
		}
	}

	tests := []struct {
		name    string
		tls     *RouteTLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil TLS config",
			tls:     nil,
			wantErr: false,
		},
		{
			name: "valid TLS with cert and key files",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				SNIHosts: []string{"grpc.example.com"},
			},
			wantErr: false,
		},
		{
			name: "missing key file",
			tls: &RouteTLSConfig{
				CertFile: "/path/to/cert.pem",
				SNIHosts: []string{"grpc.example.com"},
			},
			wantErr: true,
			errMsg:  "keyFile is required",
		},
		{
			name: "invalid min TLS version",
			tls: &RouteTLSConfig{
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid TLS version",
		},
		{
			name: "valid Vault config for gRPC route",
			tls: &RouteTLSConfig{
				SNIHosts: []string{"grpc.example.com"},
				Vault: &VaultTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "grpc-role",
					CommonName: "grpc.example.com",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(baseConfig(tt.tls))
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

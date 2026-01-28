package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, "gateway.avapigw.io/v1", cfg.APIVersion)
	assert.Equal(t, "Gateway", cfg.Kind)
	assert.Equal(t, "default-gateway", cfg.Metadata.Name)
	assert.Len(t, cfg.Spec.Listeners, 1)
	assert.Equal(t, "http", cfg.Spec.Listeners[0].Name)
	assert.Equal(t, 8080, cfg.Spec.Listeners[0].Port)
	assert.Equal(t, "HTTP", cfg.Spec.Listeners[0].Protocol)
	assert.NotNil(t, cfg.Spec.Observability)
	assert.NotNil(t, cfg.Spec.Observability.Metrics)
	assert.True(t, cfg.Spec.Observability.Metrics.Enabled)
}

func TestURIMatch_MatchType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uri      URIMatch
		expected string
	}{
		{
			name:     "exact match",
			uri:      URIMatch{Exact: "/api/v1"},
			expected: "exact",
		},
		{
			name:     "prefix match",
			uri:      URIMatch{Prefix: "/api/"},
			expected: "prefix",
		},
		{
			name:     "regex match",
			uri:      URIMatch{Regex: "^/api/.*"},
			expected: "regex",
		},
		{
			name:     "empty match",
			uri:      URIMatch{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.uri.MatchType())
		})
	}
}

func TestURIMatch_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		uri      URIMatch
		expected bool
	}{
		{
			name:     "empty",
			uri:      URIMatch{},
			expected: true,
		},
		{
			name:     "with exact",
			uri:      URIMatch{Exact: "/api"},
			expected: false,
		},
		{
			name:     "with prefix",
			uri:      URIMatch{Prefix: "/api/"},
			expected: false,
		},
		{
			name:     "with regex",
			uri:      URIMatch{Regex: ".*"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.uri.IsEmpty())
		})
	}
}

func TestRouteMatch_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    RouteMatch
		expected bool
	}{
		{
			name:     "empty",
			match:    RouteMatch{},
			expected: true,
		},
		{
			name:     "with URI",
			match:    RouteMatch{URI: &URIMatch{Exact: "/api"}},
			expected: false,
		},
		{
			name:     "with empty URI",
			match:    RouteMatch{URI: &URIMatch{}},
			expected: true,
		},
		{
			name:     "with methods",
			match:    RouteMatch{Methods: []string{"GET"}},
			expected: false,
		},
		{
			name:     "with headers",
			match:    RouteMatch{Headers: []HeaderMatch{{Name: "X-Test"}}},
			expected: false,
		},
		{
			name:     "with query params",
			match:    RouteMatch{QueryParams: []QueryParamMatch{{Name: "id"}}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.match.IsEmpty())
		})
	}
}

func TestDuration_UnmarshalYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "seconds",
			input:    "30s",
			expected: 30 * time.Second,
			wantErr:  false,
		},
		{
			name:     "minutes",
			input:    "5m",
			expected: 5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "hours",
			input:    "1h",
			expected: time.Hour,
			wantErr:  false,
		},
		{
			name:     "milliseconds",
			input:    "100ms",
			expected: 100 * time.Millisecond,
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			input:    "invalid",
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var d Duration
			yamlData := []byte(tt.input)
			err := yaml.Unmarshal(yamlData, &d)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, d.Duration())
			}
		})
	}
}

func TestDuration_MarshalYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration Duration
		expected string
	}{
		{
			name:     "seconds",
			duration: Duration(30 * time.Second),
			expected: "30s",
		},
		{
			name:     "minutes",
			duration: Duration(5 * time.Minute),
			expected: "5m0s",
		},
		{
			name:     "zero",
			duration: Duration(0),
			expected: "0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.duration.MarshalYAML()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "quoted seconds",
			input:    `"30s"`,
			expected: 30 * time.Second,
			wantErr:  false,
		},
		{
			name:     "quoted minutes",
			input:    `"5m"`,
			expected: 5 * time.Minute,
			wantErr:  false,
		},
		{
			name:     "empty quoted",
			input:    `""`,
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "null",
			input:    `null`,
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			input:    `"invalid"`,
			expected: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var d Duration
			err := json.Unmarshal([]byte(tt.input), &d)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, d.Duration())
			}
		})
	}
}

func TestDuration_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		duration Duration
		expected string
	}{
		{
			name:     "seconds",
			duration: Duration(30 * time.Second),
			expected: `"30s"`,
		},
		{
			name:     "zero",
			duration: Duration(0),
			expected: `"0s"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := tt.duration.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(result))
		})
	}
}

func TestDuration_Duration(t *testing.T) {
	t.Parallel()

	d := Duration(5 * time.Second)
	assert.Equal(t, 5*time.Second, d.Duration())
}

func TestGatewayConfig_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: Metadata{
			Name:   "test-gateway",
			Labels: map[string]string{"env": "test"},
		},
		Spec: GatewaySpec{
			Listeners: []Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
					Hosts:    []string{"*"},
				},
			},
			Routes: []Route{
				{
					Name: "test-route",
					Match: []RouteMatch{
						{
							URI:     &URIMatch{Prefix: "/api/"},
							Methods: []string{"GET", "POST"},
						},
					},
					Route: []RouteDestination{
						{
							Destination: Destination{
								Host: "backend",
								Port: 8080,
							},
							Weight: 100,
						},
					},
					Timeout: Duration(30 * time.Second),
				},
			},
		},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GatewayConfig
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.APIVersion, restored.APIVersion)
	assert.Equal(t, original.Kind, restored.Kind)
	assert.Equal(t, original.Metadata.Name, restored.Metadata.Name)
	assert.Len(t, restored.Spec.Listeners, 1)
	assert.Len(t, restored.Spec.Routes, 1)
}

func TestGatewayConfig_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := &GatewayConfig{
		APIVersion: "gateway.avapigw.io/v1",
		Kind:       "Gateway",
		Metadata: Metadata{
			Name: "test-gateway",
		},
		Spec: GatewaySpec{
			Listeners: []Listener{
				{
					Name:     "http",
					Port:     8080,
					Protocol: "HTTP",
				},
			},
		},
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GatewayConfig
	err = json.Unmarshal(jsonData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.APIVersion, restored.APIVersion)
	assert.Equal(t, original.Kind, restored.Kind)
	assert.Equal(t, original.Metadata.Name, restored.Metadata.Name)
}

func TestLoadBalancerAlgorithm_Constants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "roundRobin", LoadBalancerRoundRobin)
	assert.Equal(t, "weighted", LoadBalancerWeighted)
	assert.Equal(t, "leastConn", LoadBalancerLeastConn)
	assert.Equal(t, "random", LoadBalancerRandom)
}

func TestRateLimitConfig(t *testing.T) {
	t.Parallel()

	cfg := RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 100,
		Burst:             10,
		PerClient:         true,
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 100, cfg.RequestsPerSecond)
	assert.Equal(t, 10, cfg.Burst)
	assert.True(t, cfg.PerClient)
}

func TestCircuitBreakerConfig(t *testing.T) {
	t.Parallel()

	cfg := CircuitBreakerConfig{
		Enabled:          true,
		Threshold:        5,
		Timeout:          Duration(30 * time.Second),
		HalfOpenRequests: 3,
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 5, cfg.Threshold)
	assert.Equal(t, 30*time.Second, cfg.Timeout.Duration())
	assert.Equal(t, 3, cfg.HalfOpenRequests)
}

func TestCORSConfig(t *testing.T) {
	t.Parallel()

	cfg := CORSConfig{
		AllowOrigins:     []string{"http://example.com"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Content-Type"},
		ExposeHeaders:    []string{"X-Request-ID"},
		MaxAge:           3600,
		AllowCredentials: true,
	}

	assert.Equal(t, []string{"http://example.com"}, cfg.AllowOrigins)
	assert.Equal(t, []string{"GET", "POST"}, cfg.AllowMethods)
	assert.Equal(t, []string{"Content-Type"}, cfg.AllowHeaders)
	assert.Equal(t, []string{"X-Request-ID"}, cfg.ExposeHeaders)
	assert.Equal(t, 3600, cfg.MaxAge)
	assert.True(t, cfg.AllowCredentials)
}

func TestRedirectConfig(t *testing.T) {
	t.Parallel()

	cfg := RedirectConfig{
		URI:        "/new-path",
		Code:       301,
		Scheme:     "https",
		Host:       "example.com",
		Port:       443,
		StripQuery: true,
	}

	assert.Equal(t, "/new-path", cfg.URI)
	assert.Equal(t, 301, cfg.Code)
	assert.Equal(t, "https", cfg.Scheme)
	assert.Equal(t, "example.com", cfg.Host)
	assert.Equal(t, 443, cfg.Port)
	assert.True(t, cfg.StripQuery)
}

func TestRewriteConfig(t *testing.T) {
	t.Parallel()

	cfg := RewriteConfig{
		URI:       "/api/v2/{path}",
		Authority: "backend.internal",
	}

	assert.Equal(t, "/api/v2/{path}", cfg.URI)
	assert.Equal(t, "backend.internal", cfg.Authority)
}

func TestDirectResponseConfig(t *testing.T) {
	t.Parallel()

	cfg := DirectResponseConfig{
		Status:  200,
		Body:    `{"status":"ok"}`,
		Headers: map[string]string{"Content-Type": "application/json"},
	}

	assert.Equal(t, 200, cfg.Status)
	assert.Equal(t, `{"status":"ok"}`, cfg.Body)
	assert.Equal(t, "application/json", cfg.Headers["Content-Type"])
}

func TestHeaderManipulation(t *testing.T) {
	t.Parallel()

	cfg := HeaderManipulation{
		Request: &HeaderOperation{
			Set:    map[string]string{"X-Custom": "value"},
			Add:    map[string]string{"X-Added": "value"},
			Remove: []string{"X-Remove"},
		},
		Response: &HeaderOperation{
			Set: map[string]string{"X-Response": "value"},
		},
	}

	assert.NotNil(t, cfg.Request)
	assert.NotNil(t, cfg.Response)
	assert.Equal(t, "value", cfg.Request.Set["X-Custom"])
	assert.Equal(t, "value", cfg.Request.Add["X-Added"])
	assert.Contains(t, cfg.Request.Remove, "X-Remove")
}

func TestFaultInjection(t *testing.T) {
	t.Parallel()

	cfg := FaultInjection{
		Delay: &FaultDelay{
			FixedDelay: Duration(100 * time.Millisecond),
			Percentage: 10,
		},
		Abort: &FaultAbort{
			HTTPStatus: 500,
			Percentage: 5,
		},
	}

	assert.NotNil(t, cfg.Delay)
	assert.NotNil(t, cfg.Abort)
	assert.Equal(t, 100*time.Millisecond, cfg.Delay.FixedDelay.Duration())
	assert.Equal(t, float64(10), cfg.Delay.Percentage)
	assert.Equal(t, 500, cfg.Abort.HTTPStatus)
	assert.Equal(t, float64(5), cfg.Abort.Percentage)
}

func TestMirrorConfig(t *testing.T) {
	t.Parallel()

	cfg := MirrorConfig{
		Destination: Destination{
			Host: "mirror-backend",
			Port: 8080,
		},
		Percentage: 10,
	}

	assert.Equal(t, "mirror-backend", cfg.Destination.Host)
	assert.Equal(t, 8080, cfg.Destination.Port)
	assert.Equal(t, float64(10), cfg.Percentage)
}

func TestObservabilityConfig(t *testing.T) {
	t.Parallel()

	cfg := ObservabilityConfig{
		Metrics: &MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
			Port:    9090,
		},
		Tracing: &TracingConfig{
			Enabled:      true,
			SamplingRate: 0.1,
			OTLPEndpoint: "localhost:4317",
			ServiceName:  "gateway",
		},
		Logging: &LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}

	assert.NotNil(t, cfg.Metrics)
	assert.NotNil(t, cfg.Tracing)
	assert.NotNil(t, cfg.Logging)
	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, "/metrics", cfg.Metrics.Path)
	assert.True(t, cfg.Tracing.Enabled)
	assert.Equal(t, 0.1, cfg.Tracing.SamplingRate)
	assert.Equal(t, "info", cfg.Logging.Level)
}

func TestBackend(t *testing.T) {
	t.Parallel()

	cfg := Backend{
		Name: "user-service",
		Hosts: []BackendHost{
			{
				Address: "10.0.0.1",
				Port:    8080,
				Weight:  50,
			},
			{
				Address: "10.0.0.2",
				Port:    8080,
				Weight:  50,
			},
		},
		HealthCheck: &HealthCheck{
			Path:               "/health",
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
		LoadBalancer: &LoadBalancer{
			Algorithm: LoadBalancerRoundRobin,
		},
	}

	assert.Equal(t, "user-service", cfg.Name)
	assert.Len(t, cfg.Hosts, 2)
	assert.NotNil(t, cfg.HealthCheck)
	assert.NotNil(t, cfg.LoadBalancer)
	assert.Equal(t, "/health", cfg.HealthCheck.Path)
	assert.Equal(t, LoadBalancerRoundRobin, cfg.LoadBalancer.Algorithm)
}

func TestRetryPolicy(t *testing.T) {
	t.Parallel()

	cfg := RetryPolicy{
		Attempts:      3,
		PerTryTimeout: Duration(10 * time.Second),
		RetryOn:       "5xx,reset",
	}

	assert.Equal(t, 3, cfg.Attempts)
	assert.Equal(t, 10*time.Second, cfg.PerTryTimeout.Duration())
	assert.Equal(t, "5xx,reset", cfg.RetryOn)
}

func TestMaxSessionsConfig(t *testing.T) {
	t.Parallel()

	cfg := MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 100,
		QueueSize:     50,
		QueueTimeout:  Duration(30 * time.Second),
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, 100, cfg.MaxConcurrent)
	assert.Equal(t, 50, cfg.QueueSize)
	assert.Equal(t, 30*time.Second, cfg.QueueTimeout.Duration())
}

func TestMaxSessionsConfig_GetEffectiveQueueTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *MaxSessionsConfig
		expected time.Duration
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: DefaultMaxSessionsQueueTimeout,
		},
		{
			name: "zero timeout",
			cfg: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueTimeout:  0,
			},
			expected: DefaultMaxSessionsQueueTimeout,
		},
		{
			name: "custom timeout",
			cfg: &MaxSessionsConfig{
				Enabled:       true,
				MaxConcurrent: 100,
				QueueTimeout:  Duration(60 * time.Second),
			},
			expected: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveQueueTimeout())
		})
	}
}

func TestMaxSessionsConfig_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := &MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 100,
		QueueSize:     50,
		QueueTimeout:  Duration(30 * time.Second),
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored MaxSessionsConfig
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Enabled, restored.Enabled)
	assert.Equal(t, original.MaxConcurrent, restored.MaxConcurrent)
	assert.Equal(t, original.QueueSize, restored.QueueSize)
	assert.Equal(t, original.QueueTimeout.Duration(), restored.QueueTimeout.Duration())
}

func TestMaxSessionsConfig_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := &MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 100,
		QueueSize:     50,
		QueueTimeout:  Duration(30 * time.Second),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored MaxSessionsConfig
	err = json.Unmarshal(jsonData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Enabled, restored.Enabled)
	assert.Equal(t, original.MaxConcurrent, restored.MaxConcurrent)
	assert.Equal(t, original.QueueSize, restored.QueueSize)
	assert.Equal(t, original.QueueTimeout.Duration(), restored.QueueTimeout.Duration())
}

func TestBackend_WithMaxSessionsAndRateLimit(t *testing.T) {
	t.Parallel()

	cfg := Backend{
		Name: "user-service",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 8080, Weight: 50},
		},
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 100,
			QueueSize:     50,
			QueueTimeout:  Duration(30 * time.Second),
		},
		RateLimit: &RateLimitConfig{
			Enabled:           true,
			RequestsPerSecond: 1000,
			Burst:             100,
		},
	}

	assert.Equal(t, "user-service", cfg.Name)
	assert.NotNil(t, cfg.MaxSessions)
	assert.True(t, cfg.MaxSessions.Enabled)
	assert.Equal(t, 100, cfg.MaxSessions.MaxConcurrent)
	assert.NotNil(t, cfg.RateLimit)
	assert.True(t, cfg.RateLimit.Enabled)
	assert.Equal(t, 1000, cfg.RateLimit.RequestsPerSecond)
}

func TestRoute_WithMaxSessions(t *testing.T) {
	t.Parallel()

	route := Route{
		Name: "test-route",
		Match: []RouteMatch{
			{URI: &URIMatch{Prefix: "/api/"}},
		},
		Route: []RouteDestination{
			{Destination: Destination{Host: "backend", Port: 8080}},
		},
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 50,
		},
	}

	assert.Equal(t, "test-route", route.Name)
	assert.NotNil(t, route.MaxSessions)
	assert.True(t, route.MaxSessions.Enabled)
	assert.Equal(t, 50, route.MaxSessions.MaxConcurrent)
}

func TestGatewaySpec_WithMaxSessions(t *testing.T) {
	t.Parallel()

	spec := GatewaySpec{
		Listeners: []Listener{
			{Name: "http", Port: 8080, Protocol: "HTTP"},
		},
		MaxSessions: &MaxSessionsConfig{
			Enabled:       true,
			MaxConcurrent: 1000,
			QueueSize:     100,
			QueueTimeout:  Duration(30 * time.Second),
		},
	}

	assert.NotNil(t, spec.MaxSessions)
	assert.True(t, spec.MaxSessions.Enabled)
	assert.Equal(t, 1000, spec.MaxSessions.MaxConcurrent)
	assert.Equal(t, 100, spec.MaxSessions.QueueSize)
}

func TestRoute_HasTLSOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    Route
		expected bool
	}{
		{
			name:     "nil TLS config",
			route:    Route{Name: "test"},
			expected: false,
		},
		{
			name: "empty TLS config",
			route: Route{
				Name: "test",
				TLS:  &RouteTLSConfig{},
			},
			expected: false,
		},
		{
			name: "TLS with cert file only",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with key file only",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					KeyFile: "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with both cert and key files",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with Vault disabled",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					Vault: &VaultTLSConfig{
						Enabled: false,
					},
				},
			},
			expected: false,
		},
		{
			name: "TLS with Vault enabled",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					Vault: &VaultTLSConfig{
						Enabled:    true,
						PKIMount:   "pki",
						Role:       "my-role",
						CommonName: "example.com",
					},
				},
			},
			expected: true,
		},
		{
			name: "TLS with SNI hosts only (no cert)",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					SNIHosts: []string{"api.example.com"},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.route.HasTLSOverride())
		})
	}
}

func TestRoute_GetEffectiveSNIHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    Route
		expected []string
	}{
		{
			name:     "nil TLS config",
			route:    Route{Name: "test"},
			expected: nil,
		},
		{
			name: "empty TLS config",
			route: Route{
				Name: "test",
				TLS:  &RouteTLSConfig{},
			},
			expected: nil,
		},
		{
			name: "TLS with empty SNI hosts",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{},
				},
			},
			expected: nil,
		},
		{
			name: "TLS with single SNI host",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"api.example.com"},
				},
			},
			expected: []string{"api.example.com"},
		},
		{
			name: "TLS with multiple SNI hosts",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"api.example.com", "www.example.com", "*.example.com"},
				},
			},
			expected: []string{"api.example.com", "www.example.com", "*.example.com"},
		},
		{
			name: "TLS with wildcard SNI host",
			route: Route{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"*.example.com"},
				},
			},
			expected: []string{"*.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.route.GetEffectiveSNIHosts()
			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

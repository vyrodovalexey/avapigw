package config

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultGRPCListenerConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultGRPCListenerConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, uint32(100), cfg.MaxConcurrentStreams)
	assert.Equal(t, 4*1024*1024, cfg.MaxRecvMsgSize)
	assert.Equal(t, 4*1024*1024, cfg.MaxSendMsgSize)
	assert.False(t, cfg.Reflection)
	assert.True(t, cfg.HealthCheck)
	assert.NotNil(t, cfg.Keepalive)
	assert.Equal(t, Duration(30*time.Second), cfg.Keepalive.Time)
	assert.Equal(t, Duration(10*time.Second), cfg.Keepalive.Timeout)
	assert.False(t, cfg.Keepalive.PermitWithoutStream)
	assert.Equal(t, Duration(5*time.Minute), cfg.Keepalive.MaxConnectionIdle)
	assert.Equal(t, Duration(30*time.Minute), cfg.Keepalive.MaxConnectionAge)
	assert.Equal(t, Duration(5*time.Second), cfg.Keepalive.MaxConnectionAgeGrace)
}

func TestDefaultGRPCHealthCheckConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultGRPCHealthCheckConfig()

	assert.NotNil(t, cfg)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, "", cfg.Service)
	assert.Equal(t, Duration(10*time.Second), cfg.Interval)
	assert.Equal(t, Duration(5*time.Second), cfg.Timeout)
	assert.Equal(t, 2, cfg.HealthyThreshold)
	assert.Equal(t, 3, cfg.UnhealthyThreshold)
}

func TestDefaultGRPCRetryPolicy(t *testing.T) {
	t.Parallel()

	cfg := DefaultGRPCRetryPolicy()

	assert.NotNil(t, cfg)
	assert.Equal(t, 3, cfg.Attempts)
	assert.Equal(t, Duration(10*time.Second), cfg.PerTryTimeout)
	assert.Equal(t, "unavailable,resource-exhausted", cfg.RetryOn)
	assert.Equal(t, Duration(100*time.Millisecond), cfg.BackoffBaseInterval)
	assert.Equal(t, Duration(1*time.Second), cfg.BackoffMaxInterval)
}

func TestStringMatch_MatchType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    *StringMatch
		expected string
	}{
		{
			name:     "nil match",
			match:    nil,
			expected: "",
		},
		{
			name:     "exact match",
			match:    &StringMatch{Exact: "test.Service"},
			expected: "exact",
		},
		{
			name:     "prefix match",
			match:    &StringMatch{Prefix: "test."},
			expected: "prefix",
		},
		{
			name:     "regex match",
			match:    &StringMatch{Regex: "^test\\..*"},
			expected: "regex",
		},
		{
			name:     "empty match",
			match:    &StringMatch{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.match.MatchType())
		})
	}
}

func TestStringMatch_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    *StringMatch
		expected bool
	}{
		{
			name:     "nil match",
			match:    nil,
			expected: true,
		},
		{
			name:     "empty match",
			match:    &StringMatch{},
			expected: true,
		},
		{
			name:     "with exact",
			match:    &StringMatch{Exact: "test"},
			expected: false,
		},
		{
			name:     "with prefix",
			match:    &StringMatch{Prefix: "test"},
			expected: false,
		},
		{
			name:     "with regex",
			match:    &StringMatch{Regex: ".*"},
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

func TestStringMatch_IsWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    *StringMatch
		expected bool
	}{
		{
			name:     "nil match",
			match:    nil,
			expected: false,
		},
		{
			name:     "exact wildcard",
			match:    &StringMatch{Exact: "*"},
			expected: true,
		},
		{
			name:     "prefix wildcard",
			match:    &StringMatch{Prefix: "*"},
			expected: true,
		},
		{
			name:     "not wildcard",
			match:    &StringMatch{Exact: "test"},
			expected: false,
		},
		{
			name:     "empty match",
			match:    &StringMatch{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.match.IsWildcard())
		})
	}
}

func TestGRPCRouteMatch_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		match    GRPCRouteMatch
		expected bool
	}{
		{
			name:     "empty match",
			match:    GRPCRouteMatch{},
			expected: true,
		},
		{
			name: "with service",
			match: GRPCRouteMatch{
				Service: &StringMatch{Exact: "test.Service"},
			},
			expected: false,
		},
		{
			name: "with method",
			match: GRPCRouteMatch{
				Method: &StringMatch{Exact: "GetUser"},
			},
			expected: false,
		},
		{
			name: "with metadata",
			match: GRPCRouteMatch{
				Metadata: []MetadataMatch{{Name: "x-custom"}},
			},
			expected: false,
		},
		{
			name: "with authority",
			match: GRPCRouteMatch{
				Authority: &StringMatch{Exact: "api.example.com"},
			},
			expected: false,
		},
		{
			name: "with without headers",
			match: GRPCRouteMatch{
				WithoutHeaders: []string{"x-internal"},
			},
			expected: false,
		},
		{
			name: "with empty service",
			match: GRPCRouteMatch{
				Service: &StringMatch{},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.match.IsEmpty())
		})
	}
}

func TestGRPCListenerConfig_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := &GRPCListenerConfig{
		MaxConcurrentStreams: 200,
		MaxRecvMsgSize:       8 * 1024 * 1024,
		MaxSendMsgSize:       8 * 1024 * 1024,
		Keepalive: &GRPCKeepaliveConfig{
			Time:                  Duration(60 * time.Second),
			Timeout:               Duration(20 * time.Second),
			PermitWithoutStream:   true,
			MaxConnectionIdle:     Duration(10 * time.Minute),
			MaxConnectionAge:      Duration(1 * time.Hour),
			MaxConnectionAgeGrace: Duration(10 * time.Second),
		},
		Reflection:  true,
		HealthCheck: true,
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GRPCListenerConfig
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.MaxConcurrentStreams, restored.MaxConcurrentStreams)
	assert.Equal(t, original.MaxRecvMsgSize, restored.MaxRecvMsgSize)
	assert.Equal(t, original.MaxSendMsgSize, restored.MaxSendMsgSize)
	assert.Equal(t, original.Reflection, restored.Reflection)
	assert.Equal(t, original.HealthCheck, restored.HealthCheck)
	assert.NotNil(t, restored.Keepalive)
	assert.Equal(t, original.Keepalive.Time, restored.Keepalive.Time)
}

func TestGRPCListenerConfig_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	original := &GRPCListenerConfig{
		MaxConcurrentStreams: 150,
		MaxRecvMsgSize:       2 * 1024 * 1024,
		MaxSendMsgSize:       2 * 1024 * 1024,
		Reflection:           false,
		HealthCheck:          true,
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GRPCListenerConfig
	err = json.Unmarshal(jsonData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.MaxConcurrentStreams, restored.MaxConcurrentStreams)
	assert.Equal(t, original.MaxRecvMsgSize, restored.MaxRecvMsgSize)
	assert.Equal(t, original.MaxSendMsgSize, restored.MaxSendMsgSize)
}

func TestGRPCRoute_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := GRPCRoute{
		Name: "test-route",
		Match: []GRPCRouteMatch{
			{
				Service: &StringMatch{Prefix: "test."},
				Method:  &StringMatch{Exact: "GetUser"},
				Metadata: []MetadataMatch{
					{Name: "x-custom", Exact: "value"},
				},
			},
		},
		Route: []RouteDestination{
			{
				Destination: Destination{Host: "backend", Port: 8080},
				Weight:      100,
			},
		},
		Timeout: Duration(30 * time.Second),
		Retries: &GRPCRetryPolicy{
			Attempts:            3,
			PerTryTimeout:       Duration(10 * time.Second),
			RetryOn:             "unavailable",
			BackoffBaseInterval: Duration(100 * time.Millisecond),
			BackoffMaxInterval:  Duration(1 * time.Second),
		},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GRPCRoute
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Name, restored.Name)
	assert.Len(t, restored.Match, 1)
	assert.Len(t, restored.Route, 1)
	assert.Equal(t, original.Timeout, restored.Timeout)
	assert.NotNil(t, restored.Retries)
	assert.Equal(t, original.Retries.Attempts, restored.Retries.Attempts)
}

func TestGRPCBackend_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := GRPCBackend{
		Name: "user-service",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 8080, Weight: 50},
			{Address: "10.0.0.2", Port: 8080, Weight: 50},
		},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			Service:            "user.UserService",
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
		LoadBalancer: &LoadBalancer{
			Algorithm: LoadBalancerRoundRobin,
		},
		ConnectionPool: &GRPCConnectionPoolConfig{
			MaxIdleConns:    10,
			MaxConnsPerHost: 100,
			IdleConnTimeout: Duration(5 * time.Minute),
		},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored GRPCBackend
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Name, restored.Name)
	assert.Len(t, restored.Hosts, 2)
	assert.NotNil(t, restored.HealthCheck)
	assert.NotNil(t, restored.LoadBalancer)
	assert.NotNil(t, restored.ConnectionPool)
	assert.Equal(t, original.HealthCheck.Service, restored.HealthCheck.Service)
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()

	cfg := TLSConfig{
		Enabled:            true,
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		CAFile:             "/path/to/ca.pem",
		InsecureSkipVerify: false,
	}

	assert.True(t, cfg.Enabled)
	assert.Equal(t, "/path/to/cert.pem", cfg.CertFile)
	assert.Equal(t, "/path/to/key.pem", cfg.KeyFile)
	assert.Equal(t, "/path/to/ca.pem", cfg.CAFile)
	assert.False(t, cfg.InsecureSkipVerify)
}

func TestMetadataMatch(t *testing.T) {
	t.Parallel()

	present := true
	absent := true

	tests := []struct {
		name  string
		match MetadataMatch
	}{
		{
			name:  "exact match",
			match: MetadataMatch{Name: "x-custom", Exact: "value"},
		},
		{
			name:  "prefix match",
			match: MetadataMatch{Name: "x-custom", Prefix: "val"},
		},
		{
			name:  "regex match",
			match: MetadataMatch{Name: "x-custom", Regex: "^val.*"},
		},
		{
			name:  "present match",
			match: MetadataMatch{Name: "x-custom", Present: &present},
		},
		{
			name:  "absent match",
			match: MetadataMatch{Name: "x-custom", Absent: &absent},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, "x-custom", tt.match.Name)
		})
	}
}

func TestGRPCKeepaliveConfig_Duration(t *testing.T) {
	t.Parallel()

	cfg := &GRPCKeepaliveConfig{
		Time:                  Duration(30 * time.Second),
		Timeout:               Duration(10 * time.Second),
		MaxConnectionIdle:     Duration(5 * time.Minute),
		MaxConnectionAge:      Duration(30 * time.Minute),
		MaxConnectionAgeGrace: Duration(5 * time.Second),
	}

	assert.Equal(t, 30*time.Second, cfg.Time.Duration())
	assert.Equal(t, 10*time.Second, cfg.Timeout.Duration())
	assert.Equal(t, 5*time.Minute, cfg.MaxConnectionIdle.Duration())
	assert.Equal(t, 30*time.Minute, cfg.MaxConnectionAge.Duration())
	assert.Equal(t, 5*time.Second, cfg.MaxConnectionAgeGrace.Duration())
}

func TestGRPCConnectionPoolConfig(t *testing.T) {
	t.Parallel()

	cfg := &GRPCConnectionPoolConfig{
		MaxIdleConns:    10,
		MaxConnsPerHost: 100,
		IdleConnTimeout: Duration(5 * time.Minute),
	}

	assert.Equal(t, 10, cfg.MaxIdleConns)
	assert.Equal(t, 100, cfg.MaxConnsPerHost)
	assert.Equal(t, 5*time.Minute, cfg.IdleConnTimeout.Duration())
}

func TestProtocolConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "HTTP", ProtocolHTTP)
	assert.Equal(t, "HTTPS", ProtocolHTTPS)
	assert.Equal(t, "HTTP2", ProtocolHTTP2)
	assert.Equal(t, "GRPC", ProtocolGRPC)
}

func TestTLSModeConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "SIMPLE", TLSModeSimple)
	assert.Equal(t, "MUTUAL", TLSModeMutual)
	assert.Equal(t, "OPTIONAL_MUTUAL", TLSModeOptionalMutual)
	assert.Equal(t, "INSECURE", TLSModeInsecure)
}

func TestTLSConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *TLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "disabled config",
			config:  &TLSConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid simple mode",
			config: &TLSConfig{
				Enabled:  true,
				Mode:     TLSModeSimple,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			wantErr: false,
		},
		{
			name: "valid mutual mode",
			config: &TLSConfig{
				Enabled:  true,
				Mode:     TLSModeMutual,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
				CAFile:   "/path/to/ca.pem",
			},
			wantErr: false,
		},
		{
			name: "valid insecure mode",
			config: &TLSConfig{
				Enabled: true,
				Mode:    TLSModeInsecure,
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			config: &TLSConfig{
				Enabled: true,
				Mode:    "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid TLS mode",
		},
		{
			name: "missing cert file for simple mode",
			config: &TLSConfig{
				Enabled: true,
				Mode:    TLSModeSimple,
				KeyFile: "/path/to/key.pem",
			},
			wantErr: true,
			errMsg:  "certFile is required",
		},
		{
			name: "missing key file for simple mode",
			config: &TLSConfig{
				Enabled:  true,
				Mode:     TLSModeSimple,
				CertFile: "/path/to/cert.pem",
			},
			wantErr: true,
			errMsg:  "keyFile is required",
		},
		{
			name: "missing CA file for mutual mode",
			config: &TLSConfig{
				Enabled:  true,
				Mode:     TLSModeMutual,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			wantErr: true,
			errMsg:  "caFile is required",
		},
		{
			name: "invalid min version",
			config: &TLSConfig{
				Enabled:    true,
				Mode:       TLSModeSimple,
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MinVersion: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid minVersion",
		},
		{
			name: "invalid max version",
			config: &TLSConfig{
				Enabled:    true,
				Mode:       TLSModeSimple,
				CertFile:   "/path/to/cert.pem",
				KeyFile:    "/path/to/key.pem",
				MaxVersion: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid maxVersion",
		},
		{
			name: "valid with vault",
			config: &TLSConfig{
				Enabled: true,
				Mode:    TLSModeSimple,
				Vault: &VaultGRPCTLSConfig{
					Enabled:    true,
					PKIMount:   "pki",
					Role:       "server",
					CommonName: "server.example.com",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
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

func TestVaultGRPCTLSConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *VaultGRPCTLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "disabled config",
			config:  &VaultGRPCTLSConfig{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid config",
			config: &VaultGRPCTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "server",
				CommonName: "server.example.com",
			},
			wantErr: false,
		},
		{
			name: "missing pki mount",
			config: &VaultGRPCTLSConfig{
				Enabled:    true,
				Role:       "server",
				CommonName: "server.example.com",
			},
			wantErr: true,
			errMsg:  "pkiMount is required",
		},
		{
			name: "missing role",
			config: &VaultGRPCTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				CommonName: "server.example.com",
			},
			wantErr: true,
			errMsg:  "role is required",
		},
		{
			name: "missing common name",
			config: &VaultGRPCTLSConfig{
				Enabled:  true,
				PKIMount: "pki",
				Role:     "server",
			},
			wantErr: true,
			errMsg:  "commonName is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.config.Validate()
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

func TestTLSConfig_IsInsecure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *TLSConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: true,
		},
		{
			name:     "disabled config",
			config:   &TLSConfig{Enabled: false},
			expected: true,
		},
		{
			name:     "insecure mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeInsecure},
			expected: true,
		},
		{
			name:     "simple mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeSimple},
			expected: false,
		},
		{
			name:     "mutual mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeMutual},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.IsInsecure())
		})
	}
}

func TestTLSConfig_IsMutual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *TLSConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "simple mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeSimple},
			expected: false,
		},
		{
			name:     "mutual mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeMutual},
			expected: true,
		},
		{
			name:     "require client cert",
			config:   &TLSConfig{Enabled: true, RequireClientCert: true},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.IsMutual())
		})
	}
}

func TestTLSConfig_IsOptionalMutual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *TLSConfig
		expected bool
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: false,
		},
		{
			name:     "simple mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeSimple},
			expected: false,
		},
		{
			name:     "optional mutual mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeOptionalMutual},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.IsOptionalMutual())
		})
	}
}

func TestTLSConfig_GetEffectiveMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *TLSConfig
		expected string
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: TLSModeInsecure,
		},
		{
			name:     "disabled config",
			config:   &TLSConfig{Enabled: false},
			expected: TLSModeInsecure,
		},
		{
			name:     "empty mode",
			config:   &TLSConfig{Enabled: true},
			expected: TLSModeSimple,
		},
		{
			name:     "explicit mode",
			config:   &TLSConfig{Enabled: true, Mode: TLSModeMutual},
			expected: TLSModeMutual,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.GetEffectiveMode())
		})
	}
}

func TestTLSConfig_GetEffectiveMinVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *TLSConfig
		expected string
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: "TLS12",
		},
		{
			name:     "empty min version",
			config:   &TLSConfig{},
			expected: "TLS12",
		},
		{
			name:     "explicit min version",
			config:   &TLSConfig{MinVersion: "TLS13"},
			expected: "TLS13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.GetEffectiveMinVersion())
		})
	}
}

func TestTLSConfig_GetEffectiveALPN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   *TLSConfig
		expected []string
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: []string{"h2"},
		},
		{
			name:     "empty ALPN",
			config:   &TLSConfig{},
			expected: []string{"h2"},
		},
		{
			name:     "explicit ALPN",
			config:   &TLSConfig{ALPN: []string{"h2", "http/1.1"}},
			expected: []string{"h2", "http/1.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.config.GetEffectiveALPN())
		})
	}
}

func TestTLSConfig_YAMLRoundTrip(t *testing.T) {
	t.Parallel()

	original := &TLSConfig{
		Enabled:            true,
		Mode:               TLSModeMutual,
		CertFile:           "/path/to/cert.pem",
		KeyFile:            "/path/to/key.pem",
		CAFile:             "/path/to/ca.pem",
		MinVersion:         "TLS12",
		MaxVersion:         "TLS13",
		CipherSuites:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		RequireClientCert:  true,
		InsecureSkipVerify: false,
		ALPN:               []string{"h2"},
		RequireALPN:        true,
		AllowedCNs:         []string{"client.example.com"},
		AllowedSANs:        []string{"*.example.com"},
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(original)
	require.NoError(t, err)

	// Unmarshal back
	var restored TLSConfig
	err = yaml.Unmarshal(yamlData, &restored)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Enabled, restored.Enabled)
	assert.Equal(t, original.Mode, restored.Mode)
	assert.Equal(t, original.CertFile, restored.CertFile)
	assert.Equal(t, original.KeyFile, restored.KeyFile)
	assert.Equal(t, original.CAFile, restored.CAFile)
	assert.Equal(t, original.MinVersion, restored.MinVersion)
	assert.Equal(t, original.MaxVersion, restored.MaxVersion)
	assert.Equal(t, original.CipherSuites, restored.CipherSuites)
	assert.Equal(t, original.RequireClientCert, restored.RequireClientCert)
	assert.Equal(t, original.InsecureSkipVerify, restored.InsecureSkipVerify)
	assert.Equal(t, original.ALPN, restored.ALPN)
	assert.Equal(t, original.RequireALPN, restored.RequireALPN)
	assert.Equal(t, original.AllowedCNs, restored.AllowedCNs)
	assert.Equal(t, original.AllowedSANs, restored.AllowedSANs)
}

func TestGRPCRoute_HasTLSOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    GRPCRoute
		expected bool
	}{
		{
			name:     "nil TLS config",
			route:    GRPCRoute{Name: "test"},
			expected: false,
		},
		{
			name: "empty TLS config",
			route: GRPCRoute{
				Name: "test",
				TLS:  &RouteTLSConfig{},
			},
			expected: false,
		},
		{
			name: "TLS with cert file only",
			route: GRPCRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with key file only",
			route: GRPCRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					KeyFile: "/path/to/key.pem",
				},
			},
			expected: true,
		},
		{
			name: "TLS with both cert and key files",
			route: GRPCRoute{
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
			route: GRPCRoute{
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
			route: GRPCRoute{
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
			route: GRPCRoute{
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

// ============================================================================
// GRPCBackendToBackend Tests
// ============================================================================

func TestGRPCBackendToBackend_BasicConversion(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name: "user-service",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 8080, Weight: 50},
			{Address: "10.0.0.2", Port: 8080, Weight: 50},
		},
	}

	b := GRPCBackendToBackend(gb)

	assert.Equal(t, "user-service", b.Name)
	assert.Len(t, b.Hosts, 2)
	assert.Equal(t, "10.0.0.1", b.Hosts[0].Address)
	assert.Equal(t, 8080, b.Hosts[0].Port)
	assert.Equal(t, 50, b.Hosts[0].Weight)
	assert.Nil(t, b.HealthCheck)
	assert.Nil(t, b.TLS)
	assert.Nil(t, b.LoadBalancer)
	assert.Nil(t, b.CircuitBreaker)
	assert.Nil(t, b.Authentication)
}

func TestGRPCBackendToBackend_WithHealthCheckEnabled(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name: "svc",
		Hosts: []BackendHost{
			{Address: "10.0.0.1", Port: 50051},
		},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.HealthCheck)
	assert.Equal(t, "/grpc.health.v1.Health/Check", b.HealthCheck.Path)
	assert.Equal(t, Duration(10*time.Second), b.HealthCheck.Interval)
	assert.Equal(t, Duration(5*time.Second), b.HealthCheck.Timeout)
	assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
	assert.Equal(t, 3, b.HealthCheck.UnhealthyThreshold)
	assert.True(t, b.HealthCheck.UseGRPC)
	assert.Empty(t, b.HealthCheck.GRPCService)
}

func TestGRPCBackendToBackend_WithHealthCheckNil(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:        "svc",
		Hosts:       []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		HealthCheck: nil,
	}

	b := GRPCBackendToBackend(gb)

	assert.Nil(t, b.HealthCheck)
}

func TestGRPCBackendToBackend_WithHealthCheckDisabled(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled: false,
		},
	}

	b := GRPCBackendToBackend(gb)

	// When health check is not enabled, it should not be converted
	assert.Nil(t, b.HealthCheck)
}

func TestGRPCBackendToBackend_WithHealthCheckGRPCFields(
	t *testing.T,
) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			Service:            "my.custom.Service",
			Interval:           Duration(5 * time.Second),
			Timeout:            Duration(2 * time.Second),
			HealthyThreshold:   3,
			UnhealthyThreshold: 5,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.HealthCheck)
	assert.True(t, b.HealthCheck.UseGRPC)
	assert.Equal(t, "my.custom.Service", b.HealthCheck.GRPCService)
	assert.Equal(
		t,
		"/grpc.health.v1.Health/Check",
		b.HealthCheck.Path,
	)
	assert.Equal(
		t, Duration(5*time.Second), b.HealthCheck.Interval,
	)
	assert.Equal(
		t, Duration(2*time.Second), b.HealthCheck.Timeout,
	)
	assert.Equal(t, 3, b.HealthCheck.HealthyThreshold)
	assert.Equal(t, 5, b.HealthCheck.UnhealthyThreshold)
}

func TestGRPCBackendToBackend_WithTLSConfig(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		TLS: &TLSConfig{
			Enabled:            true,
			Mode:               TLSModeSimple,
			CertFile:           "/path/to/cert.pem",
			KeyFile:            "/path/to/key.pem",
			CAFile:             "/path/to/ca.pem",
			MinVersion:         "TLS12",
			MaxVersion:         "TLS13",
			CipherSuites:       []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			InsecureSkipVerify: false,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.TLS)
	assert.True(t, b.TLS.Enabled)
	assert.Equal(t, TLSModeSimple, b.TLS.Mode)
	assert.Equal(t, "/path/to/cert.pem", b.TLS.CertFile)
	assert.Equal(t, "/path/to/key.pem", b.TLS.KeyFile)
	assert.Equal(t, "/path/to/ca.pem", b.TLS.CAFile)
	assert.Equal(t, "TLS12", b.TLS.MinVersion)
	assert.Equal(t, "TLS13", b.TLS.MaxVersion)
	assert.Equal(t, []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}, b.TLS.CipherSuites)
	assert.False(t, b.TLS.InsecureSkipVerify)
	assert.Nil(t, b.TLS.Vault)
}

func TestGRPCBackendToBackend_WithTLSAndVault(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		TLS: &TLSConfig{
			Enabled:  true,
			Mode:     TLSModeSimple,
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
			Vault: &VaultGRPCTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				Role:       "server",
				CommonName: "server.example.com",
				AltNames:   []string{"localhost", "server.local"},
			},
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.TLS)
	require.NotNil(t, b.TLS.Vault)
	assert.True(t, b.TLS.Vault.Enabled)
	assert.Equal(t, "pki", b.TLS.Vault.PKIMount)
	assert.Equal(t, "server", b.TLS.Vault.Role)
	assert.Equal(t, "server.example.com", b.TLS.Vault.CommonName)
	assert.Equal(t, []string{"localhost", "server.local"}, b.TLS.Vault.AltNames)
}

func TestGRPCBackendToBackend_WithTLSVaultDisabled(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		TLS: &TLSConfig{
			Enabled: true,
			Mode:    TLSModeSimple,
			Vault: &VaultGRPCTLSConfig{
				Enabled: false,
			},
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.TLS)
	assert.Nil(t, b.TLS.Vault, "Vault should be nil when disabled")
}

func TestGRPCBackendToBackend_WithTLSNilVault(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		TLS: &TLSConfig{
			Enabled: true,
			Mode:    TLSModeSimple,
			Vault:   nil,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.TLS)
	assert.Nil(t, b.TLS.Vault)
}

func TestGRPCBackendToBackend_WithLoadBalancer(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		LoadBalancer: &LoadBalancer{
			Algorithm: LoadBalancerRoundRobin,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.LoadBalancer)
	assert.Equal(t, LoadBalancerRoundRobin, b.LoadBalancer.Algorithm)
}

func TestGRPCBackendToBackend_WithCircuitBreaker(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		CircuitBreaker: &CircuitBreakerConfig{
			Enabled:   true,
			Threshold: 5,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.CircuitBreaker)
	assert.True(t, b.CircuitBreaker.Enabled)
	assert.Equal(t, 5, b.CircuitBreaker.Threshold)
}

func TestGRPCBackendToBackend_WithAuthentication(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		Authentication: &BackendAuthConfig{
			Type: "jwt",
			JWT: &BackendJWTAuthConfig{
				Enabled:     true,
				TokenSource: "static",
				StaticToken: "test-token",
			},
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.Authentication)
	assert.Equal(t, "jwt", b.Authentication.Type)
	require.NotNil(t, b.Authentication.JWT)
	assert.True(t, b.Authentication.JWT.Enabled)
}

func TestGRPCBackendToBackend_NilTLS(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		TLS:   nil,
	}

	b := GRPCBackendToBackend(gb)

	assert.Nil(t, b.TLS)
}

// ============================================================================
// GRPCBackendToBackend HTTP Health Check Tests
// ============================================================================

func TestGRPCBackendToBackend_WithHTTPHealthCheck(t *testing.T) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "auth-svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			UseHTTP:            true,
			HTTPPath:           "/status",
			HTTPPort:           8081,
			Interval:           Duration(15 * time.Second),
			Timeout:            Duration(3 * time.Second),
			HealthyThreshold:   3,
			UnhealthyThreshold: 5,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.HealthCheck)
	assert.Equal(t, "/status", b.HealthCheck.Path)
	assert.Equal(t, 8081, b.HealthCheck.Port)
	assert.False(t, b.HealthCheck.UseGRPC)
	assert.Empty(t, b.HealthCheck.GRPCService)
	assert.Equal(t, Duration(15*time.Second), b.HealthCheck.Interval)
	assert.Equal(t, Duration(3*time.Second), b.HealthCheck.Timeout)
	assert.Equal(t, 3, b.HealthCheck.HealthyThreshold)
	assert.Equal(t, 5, b.HealthCheck.UnhealthyThreshold)
}

func TestGRPCBackendToBackend_WithHTTPHealthCheck_DefaultPath(
	t *testing.T,
) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "auth-svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			UseHTTP:            true,
			HTTPPath:           "", // empty → should default to /healthz
			HTTPPort:           9090,
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.HealthCheck)
	assert.Equal(t, "/healthz", b.HealthCheck.Path)
	assert.Equal(t, 9090, b.HealthCheck.Port)
	assert.False(t, b.HealthCheck.UseGRPC)
}

func TestGRPCBackendToBackend_WithHTTPHealthCheck_NoPort(
	t *testing.T,
) {
	t.Parallel()

	gb := GRPCBackend{
		Name:  "auth-svc",
		Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		HealthCheck: &GRPCHealthCheckConfig{
			Enabled:            true,
			UseHTTP:            true,
			HTTPPath:           "/ready",
			HTTPPort:           0, // no override → Port should be 0
			Interval:           Duration(10 * time.Second),
			Timeout:            Duration(5 * time.Second),
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		},
	}

	b := GRPCBackendToBackend(gb)

	require.NotNil(t, b.HealthCheck)
	assert.Equal(t, "/ready", b.HealthCheck.Path)
	assert.Equal(t, 0, b.HealthCheck.Port)
	assert.False(t, b.HealthCheck.UseGRPC)
	assert.Equal(t, Duration(10*time.Second), b.HealthCheck.Interval)
	assert.Equal(t, Duration(5*time.Second), b.HealthCheck.Timeout)
	assert.Equal(t, 2, b.HealthCheck.HealthyThreshold)
	assert.Equal(t, 3, b.HealthCheck.UnhealthyThreshold)
}

// ============================================================================
// GRPCBackendsToBackends Tests
// ============================================================================

func TestGRPCBackendsToBackends_EmptySlice(t *testing.T) {
	t.Parallel()

	result := GRPCBackendsToBackends([]GRPCBackend{})

	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestGRPCBackendsToBackends_NilSlice(t *testing.T) {
	t.Parallel()

	result := GRPCBackendsToBackends(nil)

	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

func TestGRPCBackendsToBackends_MultipleBackends(t *testing.T) {
	t.Parallel()

	gbs := []GRPCBackend{
		{
			Name:  "svc-1",
			Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051}},
		},
		{
			Name:  "svc-2",
			Hosts: []BackendHost{{Address: "10.0.0.2", Port: 50052}},
			HealthCheck: &GRPCHealthCheckConfig{
				Enabled:  true,
				Interval: Duration(5 * time.Second),
				Timeout:  Duration(2 * time.Second),
			},
		},
		{
			Name:  "svc-3",
			Hosts: []BackendHost{{Address: "10.0.0.3", Port: 50053}},
			TLS: &TLSConfig{
				Enabled: true,
				Mode:    TLSModeSimple,
			},
		},
	}

	result := GRPCBackendsToBackends(gbs)

	require.Len(t, result, 3)
	assert.Equal(t, "svc-1", result[0].Name)
	assert.Equal(t, "svc-2", result[1].Name)
	assert.Equal(t, "svc-3", result[2].Name)

	// Verify svc-1 has no health check
	assert.Nil(t, result[0].HealthCheck)

	// Verify svc-2 has health check
	require.NotNil(t, result[1].HealthCheck)
	assert.Equal(t, "/grpc.health.v1.Health/Check", result[1].HealthCheck.Path)

	// Verify svc-3 has TLS
	require.NotNil(t, result[2].TLS)
	assert.True(t, result[2].TLS.Enabled)
}

func TestGRPCBackendsToBackends_SingleBackend(t *testing.T) {
	t.Parallel()

	gbs := []GRPCBackend{
		{
			Name:  "single-svc",
			Hosts: []BackendHost{{Address: "10.0.0.1", Port: 50051, Weight: 100}},
		},
	}

	result := GRPCBackendsToBackends(gbs)

	require.Len(t, result, 1)
	assert.Equal(t, "single-svc", result[0].Name)
	assert.Len(t, result[0].Hosts, 1)
	assert.Equal(t, 100, result[0].Hosts[0].Weight)
}

func TestGRPCRoute_GetEffectiveSNIHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		route    GRPCRoute
		expected []string
	}{
		{
			name:     "nil TLS config",
			route:    GRPCRoute{Name: "test"},
			expected: nil,
		},
		{
			name: "empty TLS config",
			route: GRPCRoute{
				Name: "test",
				TLS:  &RouteTLSConfig{},
			},
			expected: nil,
		},
		{
			name: "TLS with empty SNI hosts",
			route: GRPCRoute{
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
			route: GRPCRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"grpc.example.com"},
				},
			},
			expected: []string{"grpc.example.com"},
		},
		{
			name: "TLS with multiple SNI hosts",
			route: GRPCRoute{
				Name: "test",
				TLS: &RouteTLSConfig{
					CertFile: "/path/to/cert.pem",
					SNIHosts: []string{"grpc.example.com", "api.example.com", "*.example.com"},
				},
			},
			expected: []string{"grpc.example.com", "api.example.com", "*.example.com"},
		},
		{
			name: "TLS with wildcard SNI host",
			route: GRPCRoute{
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

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultListenerTimeouts(t *testing.T) {
	t.Parallel()

	timeouts := DefaultListenerTimeouts()

	assert.NotNil(t, timeouts)
	assert.Equal(t, Duration(DefaultReadTimeout), timeouts.ReadTimeout)
	assert.Equal(t, Duration(DefaultReadHeaderTimeout), timeouts.ReadHeaderTimeout)
	assert.Equal(t, Duration(DefaultWriteTimeout), timeouts.WriteTimeout)
	assert.Equal(t, Duration(DefaultIdleTimeout), timeouts.IdleTimeout)
}

func TestListenerTimeouts_GetEffectiveReadTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		timeouts *ListenerTimeouts
		expected time.Duration
	}{
		{
			name:     "nil timeouts",
			timeouts: nil,
			expected: DefaultReadTimeout,
		},
		{
			name:     "zero timeout",
			timeouts: &ListenerTimeouts{ReadTimeout: 0},
			expected: DefaultReadTimeout,
		},
		{
			name:     "custom timeout",
			timeouts: &ListenerTimeouts{ReadTimeout: Duration(60 * time.Second)},
			expected: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.timeouts.GetEffectiveReadTimeout())
		})
	}
}

func TestListenerTimeouts_GetEffectiveReadHeaderTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		timeouts *ListenerTimeouts
		expected time.Duration
	}{
		{
			name:     "nil timeouts",
			timeouts: nil,
			expected: DefaultReadHeaderTimeout,
		},
		{
			name:     "zero timeout",
			timeouts: &ListenerTimeouts{ReadHeaderTimeout: 0},
			expected: DefaultReadHeaderTimeout,
		},
		{
			name:     "custom timeout",
			timeouts: &ListenerTimeouts{ReadHeaderTimeout: Duration(20 * time.Second)},
			expected: 20 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.timeouts.GetEffectiveReadHeaderTimeout())
		})
	}
}

func TestListenerTimeouts_GetEffectiveWriteTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		timeouts *ListenerTimeouts
		expected time.Duration
	}{
		{
			name:     "nil timeouts",
			timeouts: nil,
			expected: DefaultWriteTimeout,
		},
		{
			name:     "zero timeout",
			timeouts: &ListenerTimeouts{WriteTimeout: 0},
			expected: DefaultWriteTimeout,
		},
		{
			name:     "custom timeout",
			timeouts: &ListenerTimeouts{WriteTimeout: Duration(45 * time.Second)},
			expected: 45 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.timeouts.GetEffectiveWriteTimeout())
		})
	}
}

func TestListenerTimeouts_GetEffectiveIdleTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		timeouts *ListenerTimeouts
		expected time.Duration
	}{
		{
			name:     "nil timeouts",
			timeouts: nil,
			expected: DefaultIdleTimeout,
		},
		{
			name:     "zero timeout",
			timeouts: &ListenerTimeouts{IdleTimeout: 0},
			expected: DefaultIdleTimeout,
		},
		{
			name:     "custom timeout",
			timeouts: &ListenerTimeouts{IdleTimeout: Duration(180 * time.Second)},
			expected: 180 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.timeouts.GetEffectiveIdleTimeout())
		})
	}
}

func TestBackendTLSConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *BackendTLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name:    "valid simple mode",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: BackendTLSModeSimple},
			wantErr: false,
		},
		{
			name:    "valid mutual mode with certs",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: BackendTLSModeMutual, CertFile: "/cert.pem", KeyFile: "/key.pem"},
			wantErr: false,
		},
		{
			name:    "mutual mode without cert",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: BackendTLSModeMutual, KeyFile: "/key.pem"},
			wantErr: true,
			errMsg:  "certFile is required",
		},
		{
			name:    "mutual mode without key",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: BackendTLSModeMutual, CertFile: "/cert.pem"},
			wantErr: true,
			errMsg:  "keyFile is required",
		},
		{
			name:    "mutual mode with vault",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: BackendTLSModeMutual, Vault: &VaultBackendTLSConfig{Enabled: true, PKIMount: "pki", Role: "role", CommonName: "cn"}},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: "INVALID"},
			wantErr: true,
			errMsg:  "invalid backend TLS mode",
		},
		{
			name:    "invalid min version",
			cfg:     &BackendTLSConfig{Enabled: true, MinVersion: "INVALID"},
			wantErr: true,
			errMsg:  "invalid minVersion",
		},
		{
			name:    "invalid max version",
			cfg:     &BackendTLSConfig{Enabled: true, MaxVersion: "INVALID"},
			wantErr: true,
			errMsg:  "invalid maxVersion",
		},
		{
			name:    "valid TLS versions",
			cfg:     &BackendTLSConfig{Enabled: true, MinVersion: "TLS12", MaxVersion: "TLS13"},
			wantErr: false,
		},
		{
			name:    "insecure mode",
			cfg:     &BackendTLSConfig{Enabled: true, Mode: TLSModeInsecure},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestVaultBackendTLSConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *VaultBackendTLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			cfg:     nil,
			wantErr: false,
		},
		{
			name:    "disabled config",
			cfg:     &VaultBackendTLSConfig{Enabled: false},
			wantErr: false,
		},
		{
			name:    "valid config",
			cfg:     &VaultBackendTLSConfig{Enabled: true, PKIMount: "pki", Role: "role", CommonName: "cn"},
			wantErr: false,
		},
		{
			name:    "missing pki mount",
			cfg:     &VaultBackendTLSConfig{Enabled: true, Role: "role", CommonName: "cn"},
			wantErr: true,
			errMsg:  "pkiMount is required",
		},
		{
			name:    "missing role",
			cfg:     &VaultBackendTLSConfig{Enabled: true, PKIMount: "pki", CommonName: "cn"},
			wantErr: true,
			errMsg:  "role is required",
		},
		{
			name:    "missing common name",
			cfg:     &VaultBackendTLSConfig{Enabled: true, PKIMount: "pki", Role: "role"},
			wantErr: true,
			errMsg:  "commonName is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
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

func TestBackendTLSConfig_IsEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendTLSConfig
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "disabled",
			cfg:      &BackendTLSConfig{Enabled: false},
			expected: false,
		},
		{
			name:     "enabled",
			cfg:      &BackendTLSConfig{Enabled: true},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.IsEnabled())
		})
	}
}

func TestBackendTLSConfig_IsMutual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendTLSConfig
		expected bool
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: false,
		},
		{
			name:     "simple mode",
			cfg:      &BackendTLSConfig{Mode: BackendTLSModeSimple},
			expected: false,
		},
		{
			name:     "mutual mode",
			cfg:      &BackendTLSConfig{Mode: BackendTLSModeMutual},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.IsMutual())
		})
	}
}

func TestBackendTLSConfig_GetEffectiveMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendTLSConfig
		expected string
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: TLSModeInsecure,
		},
		{
			name:     "disabled",
			cfg:      &BackendTLSConfig{Enabled: false},
			expected: TLSModeInsecure,
		},
		{
			name:     "enabled with empty mode",
			cfg:      &BackendTLSConfig{Enabled: true, Mode: ""},
			expected: BackendTLSModeSimple,
		},
		{
			name:     "enabled with mutual mode",
			cfg:      &BackendTLSConfig{Enabled: true, Mode: BackendTLSModeMutual},
			expected: BackendTLSModeMutual,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveMode())
		})
	}
}

func TestBackendTLSConfig_GetEffectiveMinVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *BackendTLSConfig
		expected string
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: "TLS12",
		},
		{
			name:     "empty min version",
			cfg:      &BackendTLSConfig{MinVersion: ""},
			expected: "TLS12",
		},
		{
			name:     "custom min version",
			cfg:      &BackendTLSConfig{MinVersion: "TLS13"},
			expected: "TLS13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveMinVersion())
		})
	}
}

func TestDefaultRequestLimits(t *testing.T) {
	t.Parallel()

	limits := DefaultRequestLimits()

	assert.NotNil(t, limits)
	assert.Equal(t, int64(DefaultMaxBodySize), limits.MaxBodySize)
	assert.Equal(t, int64(DefaultMaxHeaderSize), limits.MaxHeaderSize)
}

func TestRequestLimitsConfig_GetEffectiveMaxBodySize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *RequestLimitsConfig
		expected int64
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: DefaultMaxBodySize,
		},
		{
			name:     "zero size",
			cfg:      &RequestLimitsConfig{MaxBodySize: 0},
			expected: DefaultMaxBodySize,
		},
		{
			name:     "negative size",
			cfg:      &RequestLimitsConfig{MaxBodySize: -1},
			expected: DefaultMaxBodySize,
		},
		{
			name:     "custom size",
			cfg:      &RequestLimitsConfig{MaxBodySize: 20 << 20},
			expected: 20 << 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveMaxBodySize())
		})
	}
}

func TestRequestLimitsConfig_GetEffectiveMaxHeaderSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *RequestLimitsConfig
		expected int64
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: DefaultMaxHeaderSize,
		},
		{
			name:     "zero size",
			cfg:      &RequestLimitsConfig{MaxHeaderSize: 0},
			expected: DefaultMaxHeaderSize,
		},
		{
			name:     "negative size",
			cfg:      &RequestLimitsConfig{MaxHeaderSize: -1},
			expected: DefaultMaxHeaderSize,
		},
		{
			name:     "custom size",
			cfg:      &RequestLimitsConfig{MaxHeaderSize: 2 << 20},
			expected: 2 << 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetEffectiveMaxHeaderSize())
		})
	}
}

func TestRedisRetryConfig_GetMaxRetries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *RedisRetryConfig
		expected int
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: DefaultRetryMaxRetries,
		},
		{
			name:     "zero retries",
			cfg:      &RedisRetryConfig{MaxRetries: 0},
			expected: DefaultRetryMaxRetries,
		},
		{
			name:     "negative retries",
			cfg:      &RedisRetryConfig{MaxRetries: -1},
			expected: DefaultRetryMaxRetries,
		},
		{
			name:     "custom retries",
			cfg:      &RedisRetryConfig{MaxRetries: 5},
			expected: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetMaxRetries())
		})
	}
}

func TestRedisRetryConfig_GetInitialBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *RedisRetryConfig
		expected Duration
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: Duration(DefaultRetryInitialBackoff),
		},
		{
			name:     "zero backoff",
			cfg:      &RedisRetryConfig{InitialBackoff: 0},
			expected: Duration(DefaultRetryInitialBackoff),
		},
		{
			name:     "negative backoff",
			cfg:      &RedisRetryConfig{InitialBackoff: -1},
			expected: Duration(DefaultRetryInitialBackoff),
		},
		{
			name:     "custom backoff",
			cfg:      &RedisRetryConfig{InitialBackoff: Duration(200 * time.Millisecond)},
			expected: Duration(200 * time.Millisecond),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetInitialBackoff())
		})
	}
}

func TestRedisRetryConfig_GetMaxBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *RedisRetryConfig
		expected Duration
	}{
		{
			name:     "nil config",
			cfg:      nil,
			expected: Duration(DefaultRetryMaxBackoff),
		},
		{
			name:     "zero backoff",
			cfg:      &RedisRetryConfig{MaxBackoff: 0},
			expected: Duration(DefaultRetryMaxBackoff),
		},
		{
			name:     "negative backoff",
			cfg:      &RedisRetryConfig{MaxBackoff: -1},
			expected: Duration(DefaultRetryMaxBackoff),
		},
		{
			name:     "custom backoff",
			cfg:      &RedisRetryConfig{MaxBackoff: Duration(60 * time.Second)},
			expected: Duration(60 * time.Second),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.cfg.GetMaxBackoff())
		})
	}
}

func TestBackendTLSConfig_ValidateWithVault(t *testing.T) {
	t.Parallel()

	// Test vault validation is called when enabled
	cfg := &BackendTLSConfig{
		Enabled: true,
		Mode:    BackendTLSModeSimple,
		Vault: &VaultBackendTLSConfig{
			Enabled: true,
			// Missing required fields
		},
	}

	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pkiMount is required")
}

// Tests for validator functions with 0% coverage

func TestValidator_ValidateGRPCListenerConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid gRPC listener config",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								MaxRecvMsgSize:       4 * 1024 * 1024,
								MaxSendMsgSize:       4 * 1024 * 1024,
								MaxConcurrentStreams: 100,
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "negative maxRecvMsgSize",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								MaxRecvMsgSize: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxRecvMsgSize cannot be negative",
		},
		{
			name: "negative maxSendMsgSize",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								MaxSendMsgSize: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxSendMsgSize cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateGRPCKeepaliveConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid keepalive config",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								Keepalive: &GRPCKeepaliveConfig{
									Time:                  Duration(60000000000),
									Timeout:               Duration(20000000000),
									MaxConnectionIdle:     Duration(300000000000),
									MaxConnectionAge:      Duration(3600000000000),
									MaxConnectionAgeGrace: Duration(10000000000),
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "negative keepalive time",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								Keepalive: &GRPCKeepaliveConfig{
									Time: Duration(-1),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "time cannot be negative",
		},
		{
			name: "negative keepalive timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								Keepalive: &GRPCKeepaliveConfig{
									Timeout: Duration(-1),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "timeout cannot be negative",
		},
		{
			name: "negative maxConnectionIdle",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								Keepalive: &GRPCKeepaliveConfig{
									MaxConnectionIdle: Duration(-1),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxConnectionIdle cannot be negative",
		},
		{
			name: "negative maxConnectionAge",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								Keepalive: &GRPCKeepaliveConfig{
									MaxConnectionAge: Duration(-1),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxConnectionAge cannot be negative",
		},
		{
			name: "negative maxConnectionAgeGrace",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								Keepalive: &GRPCKeepaliveConfig{
									MaxConnectionAgeGrace: Duration(-1),
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxConnectionAgeGrace cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateTLSConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "TLS enabled without certFile",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								TLS: &TLSConfig{
									Enabled: true,
									KeyFile: "/path/to/key.pem",
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "certFile is required",
		},
		{
			name: "TLS enabled without keyFile",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								TLS: &TLSConfig{
									Enabled:  true,
									CertFile: "/path/to/cert.pem",
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "keyFile is required",
		},
		{
			name: "TLS disabled - no validation",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "grpc-listener",
							Port:     50051,
							Protocol: ProtocolGRPC,
							GRPC: &GRPCListenerConfig{
								TLS: &TLSConfig{
									Enabled: false,
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateGRPCRoutes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid gRPC route",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing route name",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "route name is required",
		},
		{
			name: "duplicate route name",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service2"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50053}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "duplicate gRPC route name",
		},
		{
			name: "missing match conditions",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name:  "route1",
							Match: []GRPCRouteMatch{},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one match condition is required",
		},
		{
			name: "missing destinations",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one destination is required",
		},
		{
			name: "negative timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Timeout: Duration(-1),
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "timeout cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateGRPCRouteMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "empty match condition",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{}, // Empty match
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one match condition",
		},
		{
			name: "valid service match",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid method match",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Method: &StringMatch{Prefix: "Get"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid authority match",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Authority: &StringMatch{Exact: "api.example.com"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateStringMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "multiple match types",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test", Prefix: "test"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "only one of exact, prefix, or regex can be specified",
		},
		{
			name: "invalid regex",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Regex: "[invalid"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateMetadataMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "missing metadata name",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{
									Service: &StringMatch{Exact: "test.Service"},
									Metadata: []MetadataMatch{
										{Name: "", Exact: "value"},
									},
								},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "metadata name is required",
		},
		{
			name: "present and absent both specified",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{
									Service: &StringMatch{Exact: "test.Service"},
									Metadata: []MetadataMatch{
										{Name: "header", Present: boolPtr(true), Absent: boolPtr(true)},
									},
								},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "present and absent cannot both be specified",
		},
		{
			name: "invalid metadata regex",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{
									Service: &StringMatch{Exact: "test.Service"},
									Metadata: []MetadataMatch{
										{Name: "header", Regex: "[invalid"},
									},
								},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "regex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestValidator_ValidateGRPCRetryPolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "negative attempts",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Retries: &GRPCRetryPolicy{
								Attempts: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "attempts cannot be negative",
		},
		{
			name: "negative perTryTimeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Retries: &GRPCRetryPolicy{
								PerTryTimeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "perTryTimeout cannot be negative",
		},
		{
			name: "negative backoffBaseInterval",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Retries: &GRPCRetryPolicy{
								BackoffBaseInterval: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "backoffBaseInterval cannot be negative",
		},
		{
			name: "negative backoffMaxInterval",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Retries: &GRPCRetryPolicy{
								BackoffMaxInterval: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "backoffMaxInterval cannot be negative",
		},
		{
			name: "invalid retry status code",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Retries: &GRPCRetryPolicy{
								RetryOn: "invalid-code",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid gRPC retry status code",
		},
		{
			name: "valid retry status codes",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCRoutes: []GRPCRoute{
						{
							Name: "route1",
							Match: []GRPCRouteMatch{
								{Service: &StringMatch{Exact: "test.Service"}},
							},
							Route: []RouteDestination{
								{Destination: Destination{Host: "localhost", Port: 50052}},
							},
							Retries: &GRPCRetryPolicy{
								RetryOn: "unavailable,deadline-exceeded,internal",
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateGRPCBackends(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid gRPC backend",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing backend name",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "backend name is required",
		},
		{
			name: "duplicate backend name",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
						},
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50053},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "duplicate gRPC backend name",
		},
		{
			name: "missing hosts",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name:  "backend1",
							Hosts: []BackendHost{},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "at least one host is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateGRPCHealthCheckConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "negative interval",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							HealthCheck: &GRPCHealthCheckConfig{
								Interval: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "interval cannot be negative",
		},
		{
			name: "negative timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							HealthCheck: &GRPCHealthCheckConfig{
								Timeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "timeout cannot be negative",
		},
		{
			name: "negative healthyThreshold",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							HealthCheck: &GRPCHealthCheckConfig{
								HealthyThreshold: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "healthyThreshold cannot be negative",
		},
		{
			name: "negative unhealthyThreshold",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							HealthCheck: &GRPCHealthCheckConfig{
								UnhealthyThreshold: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "unhealthyThreshold cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateGRPCConnectionPoolConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "negative maxIdleConns",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							ConnectionPool: &GRPCConnectionPoolConfig{
								MaxIdleConns: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxIdleConns cannot be negative",
		},
		{
			name: "negative maxConnsPerHost",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							ConnectionPool: &GRPCConnectionPoolConfig{
								MaxConnsPerHost: -1,
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "maxConnsPerHost cannot be negative",
		},
		{
			name: "negative idleConnTimeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							ConnectionPool: &GRPCConnectionPoolConfig{
								IdleConnTimeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "idleConnTimeout cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateBackendTLSConfigValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid backend TLS mode",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							TLS: &TLSConfig{
								Enabled: true,
								Mode:    "INVALID",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "certFile is required",
		},
		{
			name: "mutual TLS without cert",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{Name: "grpc", Port: 50051, Protocol: ProtocolGRPC},
					},
					GRPCBackends: []GRPCBackend{
						{
							Name: "backend1",
							Hosts: []BackendHost{
								{Address: "localhost", Port: 50052},
							},
							TLS: &TLSConfig{
								Enabled: true,
								Mode:    TLSModeMutual,
								KeyFile: "/path/to/key.pem",
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "certFile is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateListenerTimeouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "negative read timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: ProtocolHTTP,
							Timeouts: &ListenerTimeouts{
								ReadTimeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "readTimeout cannot be negative",
		},
		{
			name: "negative read header timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: ProtocolHTTP,
							Timeouts: &ListenerTimeouts{
								ReadHeaderTimeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "readHeaderTimeout cannot be negative",
		},
		{
			name: "negative write timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: ProtocolHTTP,
							Timeouts: &ListenerTimeouts{
								WriteTimeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "writeTimeout cannot be negative",
		},
		{
			name: "negative idle timeout",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: ProtocolHTTP,
							Timeouts: &ListenerTimeouts{
								IdleTimeout: Duration(-1),
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "idleTimeout cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidator_ValidateListenerHosts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *GatewayConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "invalid host pattern",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: ProtocolHTTP,
							Hosts:    []string{"invalid..host"},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "hostname has empty label",
		},
		{
			name: "valid wildcard host",
			cfg: &GatewayConfig{
				APIVersion: "gateway.avapigw.io/v1",
				Kind:       "Gateway",
				Metadata:   Metadata{Name: "test"},
				Spec: GatewaySpec{
					Listeners: []Listener{
						{
							Name:     "http",
							Port:     8080,
							Protocol: ProtocolHTTP,
							Hosts:    []string{"*.example.com"},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateConfig(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

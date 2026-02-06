// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.False(t, cfg.Enabled)
	assert.Equal(t, DefaultHeartbeatInterval, cfg.HeartbeatInterval)
	assert.Equal(t, DefaultConnectionTimeout, cfg.ConnectionTimeout)
	assert.Equal(t, DefaultInitialBackoff, cfg.ReconnectBackoff.InitialInterval)
	assert.Equal(t, DefaultMaxBackoff, cfg.ReconnectBackoff.MaxInterval)
	assert.Equal(t, DefaultBackoffMultiplier, cfg.ReconnectBackoff.Multiplier)
	assert.Equal(t, DefaultMaxRetries, cfg.ReconnectBackoff.MaxRetries)
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "disabled config is always valid",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid enabled config",
			config: &Config{
				Enabled:          true,
				Address:          "localhost:50051",
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
			},
			wantErr: false,
		},
		{
			name: "missing address",
			config: &Config{
				Enabled:          true,
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
			},
			wantErr: true,
			errMsg:  "operator address is required",
		},
		{
			name: "missing gateway name",
			config: &Config{
				Enabled:          true,
				Address:          "localhost:50051",
				GatewayNamespace: "default",
			},
			wantErr: true,
			errMsg:  "gateway name is required",
		},
		{
			name: "missing gateway namespace",
			config: &Config{
				Enabled:     true,
				Address:     "localhost:50051",
				GatewayName: "test-gateway",
			},
			wantErr: true,
			errMsg:  "gateway namespace is required",
		},
		{
			name: "valid config with all fields",
			config: &Config{
				Enabled:           true,
				Address:           "localhost:50051",
				GatewayName:       "test-gateway",
				GatewayNamespace:  "default",
				GatewayVersion:    "v1.0.0",
				Namespaces:        []string{"ns1", "ns2"},
				HeartbeatInterval: 30 * time.Second,
				ConnectionTimeout: 10 * time.Second,
				Labels:            map[string]string{"env": "test"},
				Annotations:       map[string]string{"note": "test"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_ValidateWithTLS(t *testing.T) {
	// Create temporary cert files for testing
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	caFile := filepath.Join(tmpDir, "ca.pem")

	// Create dummy files
	require.NoError(t, os.WriteFile(certFile, []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key"), 0600))
	require.NoError(t, os.WriteFile(caFile, []byte("ca"), 0600))

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid TLS config",
			config: &Config{
				Enabled:          true,
				Address:          "localhost:50051",
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
				TLS: &TLSConfig{
					Enabled:  true,
					CertFile: certFile,
					KeyFile:  keyFile,
					CAFile:   caFile,
				},
			},
			wantErr: false,
		},
		{
			name: "TLS disabled is valid",
			config: &Config{
				Enabled:          true,
				Address:          "localhost:50051",
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
				TLS: &TLSConfig{
					Enabled: false,
				},
			},
			wantErr: false,
		},
		{
			name: "TLS with insecure skip verify",
			config: &Config{
				Enabled:          true,
				Address:          "localhost:50051",
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
				TLS: &TLSConfig{
					Enabled:            true,
					InsecureSkipVerify: true,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTLSConfig_Validate(t *testing.T) {
	// Create temporary cert files for testing
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")
	caFile := filepath.Join(tmpDir, "ca.pem")

	// Create dummy files
	require.NoError(t, os.WriteFile(certFile, []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(keyFile, []byte("key"), 0600))
	require.NoError(t, os.WriteFile(caFile, []byte("ca"), 0600))

	tests := []struct {
		name    string
		config  *TLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config is valid",
			config: &TLSConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config with cert and key",
			config: &TLSConfig{
				Enabled:  true,
				CertFile: certFile,
				KeyFile:  keyFile,
			},
			wantErr: false,
		},
		{
			name: "valid config with all files",
			config: &TLSConfig{
				Enabled:  true,
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   caFile,
			},
			wantErr: false,
		},
		{
			name: "cert without key",
			config: &TLSConfig{
				Enabled:  true,
				CertFile: certFile,
			},
			wantErr: true,
			errMsg:  "keyFile is required when certFile is provided",
		},
		{
			name: "key without cert",
			config: &TLSConfig{
				Enabled: true,
				KeyFile: keyFile,
			},
			wantErr: true,
			errMsg:  "certFile is required when keyFile is provided",
		},
		{
			name: "cert file not found",
			config: &TLSConfig{
				Enabled:  true,
				CertFile: "/nonexistent/cert.pem",
				KeyFile:  keyFile,
			},
			wantErr: true,
			errMsg:  "certFile not found",
		},
		{
			name: "key file not found",
			config: &TLSConfig{
				Enabled:  true,
				CertFile: certFile,
				KeyFile:  "/nonexistent/key.pem",
			},
			wantErr: true,
			errMsg:  "keyFile not found",
		},
		{
			name: "ca file not found",
			config: &TLSConfig{
				Enabled:  true,
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   "/nonexistent/ca.pem",
			},
			wantErr: true,
			errMsg:  "caFile not found",
		},
		{
			name: "insecure skip verify without files",
			config: &TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			wantErr: false,
		},
		{
			name: "server name override",
			config: &TLSConfig{
				Enabled:    true,
				ServerName: "custom.server.name",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestBackoffConfig_GetInitialInterval(t *testing.T) {
	tests := []struct {
		name     string
		config   BackoffConfig
		expected time.Duration
	}{
		{
			name:     "zero returns default",
			config:   BackoffConfig{InitialInterval: 0},
			expected: DefaultInitialBackoff,
		},
		{
			name:     "negative returns default",
			config:   BackoffConfig{InitialInterval: -1 * time.Second},
			expected: DefaultInitialBackoff,
		},
		{
			name:     "positive returns value",
			config:   BackoffConfig{InitialInterval: 5 * time.Second},
			expected: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetInitialInterval()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBackoffConfig_GetMaxInterval(t *testing.T) {
	tests := []struct {
		name     string
		config   BackoffConfig
		expected time.Duration
	}{
		{
			name:     "zero returns default",
			config:   BackoffConfig{MaxInterval: 0},
			expected: DefaultMaxBackoff,
		},
		{
			name:     "negative returns default",
			config:   BackoffConfig{MaxInterval: -1 * time.Second},
			expected: DefaultMaxBackoff,
		},
		{
			name:     "positive returns value",
			config:   BackoffConfig{MaxInterval: 60 * time.Second},
			expected: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMaxInterval()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBackoffConfig_GetMultiplier(t *testing.T) {
	tests := []struct {
		name     string
		config   BackoffConfig
		expected float64
	}{
		{
			name:     "zero returns default",
			config:   BackoffConfig{Multiplier: 0},
			expected: DefaultBackoffMultiplier,
		},
		{
			name:     "negative returns default",
			config:   BackoffConfig{Multiplier: -1.0},
			expected: DefaultBackoffMultiplier,
		},
		{
			name:     "positive returns value",
			config:   BackoffConfig{Multiplier: 3.0},
			expected: 3.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMultiplier()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBackoffConfig_GetMaxRetries(t *testing.T) {
	tests := []struct {
		name     string
		config   BackoffConfig
		expected int
	}{
		{
			name:     "zero means unlimited",
			config:   BackoffConfig{MaxRetries: 0},
			expected: 0,
		},
		{
			name:     "positive returns value",
			config:   BackoffConfig{MaxRetries: 5},
			expected: 5,
		},
		{
			name:     "negative returns value (no validation here)",
			config:   BackoffConfig{MaxRetries: -1},
			expected: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetMaxRetries()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetHeartbeatInterval(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected time.Duration
	}{
		{
			name:     "zero returns default",
			config:   Config{HeartbeatInterval: 0},
			expected: DefaultHeartbeatInterval,
		},
		{
			name:     "negative returns default",
			config:   Config{HeartbeatInterval: -1 * time.Second},
			expected: DefaultHeartbeatInterval,
		},
		{
			name:     "positive returns value",
			config:   Config{HeartbeatInterval: 60 * time.Second},
			expected: 60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetHeartbeatInterval()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetConnectionTimeout(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected time.Duration
	}{
		{
			name:     "zero returns default",
			config:   Config{ConnectionTimeout: 0},
			expected: DefaultConnectionTimeout,
		},
		{
			name:     "negative returns default",
			config:   Config{ConnectionTimeout: -1 * time.Second},
			expected: DefaultConnectionTimeout,
		},
		{
			name:     "positive returns value",
			config:   Config{ConnectionTimeout: 30 * time.Second},
			expected: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.GetConnectionTimeout()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_IsTLSEnabled(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected bool
	}{
		{
			name:     "nil TLS config",
			config:   Config{TLS: nil},
			expected: false,
		},
		{
			name:     "TLS disabled",
			config:   Config{TLS: &TLSConfig{Enabled: false}},
			expected: false,
		},
		{
			name:     "TLS enabled",
			config:   Config{TLS: &TLSConfig{Enabled: true}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.IsTLSEnabled()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetPodName(t *testing.T) {
	// Save original value
	original := os.Getenv("POD_NAME")
	defer func() {
		if original != "" {
			os.Setenv("POD_NAME", original)
		} else {
			os.Unsetenv("POD_NAME")
		}
	}()

	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "env not set",
			envValue: "",
			expected: "",
		},
		{
			name:     "env set",
			envValue: "my-pod-123",
			expected: "my-pod-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("POD_NAME", tt.envValue)
			} else {
				os.Unsetenv("POD_NAME")
			}

			cfg := &Config{}
			result := cfg.GetPodName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_GetNodeName(t *testing.T) {
	// Save original value
	original := os.Getenv("NODE_NAME")
	defer func() {
		if original != "" {
			os.Setenv("NODE_NAME", original)
		} else {
			os.Unsetenv("NODE_NAME")
		}
	}()

	tests := []struct {
		name     string
		envValue string
		expected string
	}{
		{
			name:     "env not set",
			envValue: "",
			expected: "",
		},
		{
			name:     "env set",
			envValue: "node-1",
			expected: "node-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("NODE_NAME", tt.envValue)
			} else {
				os.Unsetenv("NODE_NAME")
			}

			cfg := &Config{}
			result := cfg.GetNodeName()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_ValidateWithInvalidTLS(t *testing.T) {
	config := &Config{
		Enabled:          true,
		Address:          "localhost:50051",
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
		TLS: &TLSConfig{
			Enabled:  true,
			CertFile: "/nonexistent/cert.pem",
			KeyFile:  "/nonexistent/key.pem",
		},
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS config")
}

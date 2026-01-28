package tls

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSMode_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		mode  TLSMode
		valid bool
	}{
		{"simple", TLSModeSimple, true},
		{"mutual", TLSModeMutual, true},
		{"optional_mutual", TLSModeOptionalMutual, true},
		{"passthrough", TLSModePassthrough, true},
		{"auto_passthrough", TLSModeAutoPassthrough, true},
		{"insecure", TLSModeInsecure, true},
		{"invalid", TLSMode("INVALID"), false},
		{"empty", TLSMode(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.mode.IsValid())
		})
	}
}

func TestTLSMode_RequiresCertificate(t *testing.T) {
	tests := []struct {
		mode     TLSMode
		requires bool
	}{
		{TLSModeSimple, true},
		{TLSModeMutual, true},
		{TLSModeOptionalMutual, true},
		{TLSModePassthrough, false},
		{TLSModeAutoPassthrough, false},
		{TLSModeInsecure, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.requires, tt.mode.RequiresCertificate())
		})
	}
}

func TestTLSMode_RequiresClientCA(t *testing.T) {
	tests := []struct {
		mode     TLSMode
		requires bool
	}{
		{TLSModeSimple, false},
		{TLSModeMutual, true},
		{TLSModeOptionalMutual, true},
		{TLSModePassthrough, false},
		{TLSModeAutoPassthrough, false},
		{TLSModeInsecure, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.requires, tt.mode.RequiresClientCA())
		})
	}
}

func TestTLSVersion_IsValid(t *testing.T) {
	tests := []struct {
		version TLSVersion
		valid   bool
	}{
		{TLSVersionAuto, true},
		{TLSVersion10, true},
		{TLSVersion11, true},
		{TLSVersion12, true},
		{TLSVersion13, true},
		{TLSVersion("INVALID"), false},
		{TLSVersion(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.version), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.version.IsValid())
		})
	}
}

func TestTLSVersion_IsLegacy(t *testing.T) {
	tests := []struct {
		version TLSVersion
		legacy  bool
	}{
		{TLSVersionAuto, false},
		{TLSVersion10, true},
		{TLSVersion11, true},
		{TLSVersion12, false},
		{TLSVersion13, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.version), func(t *testing.T) {
			assert.Equal(t, tt.legacy, tt.version.IsLegacy())
		})
	}
}

func TestCertificateSource_IsValid(t *testing.T) {
	tests := []struct {
		source CertificateSource
		valid  bool
	}{
		{CertificateSourceFile, true},
		{CertificateSourceInline, true},
		{CertificateSourceVault, true},
		{CertificateSource("invalid"), false},
		{CertificateSource(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.source), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.source.IsValid())
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, TLSModeSimple, cfg.Mode)
	assert.Equal(t, TLSVersion12, cfg.MinVersion)
	assert.Equal(t, TLSVersion13, cfg.MaxVersion)
	assert.Contains(t, cfg.ALPN, "h2")
	assert.Contains(t, cfg.ALPN, "http/1.1")
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid simple mode",
			config: &Config{
				Mode:       TLSModeSimple,
				MinVersion: TLSVersion12,
				MaxVersion: TLSVersion13,
				ServerCertificate: &CertificateConfig{
					Source:   CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			config: &Config{
				Mode: TLSMode("INVALID"),
			},
			wantErr: true,
			errMsg:  "invalid TLS mode",
		},
		{
			name: "invalid min version",
			config: &Config{
				MinVersion: TLSVersion("INVALID"),
			},
			wantErr: true,
			errMsg:  "invalid TLS version",
		},
		{
			name: "min version greater than max",
			config: &Config{
				MinVersion: TLSVersion13,
				MaxVersion: TLSVersion12,
				ServerCertificate: &CertificateConfig{
					Source:   CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			wantErr: true,
			errMsg:  "cannot be greater than maxVersion",
		},
		{
			name: "simple mode without certificate",
			config: &Config{
				Mode: TLSModeSimple,
			},
			wantErr: true,
			errMsg:  "server certificate required",
		},
		{
			name: "mutual mode without client validation",
			config: &Config{
				Mode: TLSModeMutual,
				ServerCertificate: &CertificateConfig{
					Source:   CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			wantErr: true,
			errMsg:  "client validation required",
		},
		{
			name: "valid mutual mode",
			config: &Config{
				Mode: TLSModeMutual,
				ServerCertificate: &CertificateConfig{
					Source:   CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
				ClientValidation: &ClientValidationConfig{
					Enabled: true,
					CAFile:  "/path/to/ca.pem",
				},
			},
			wantErr: false,
		},
		{
			name: "insecure mode without certificate",
			config: &Config{
				Mode: TLSModeInsecure,
			},
			wantErr: false,
		},
		{
			name: "passthrough mode without certificate",
			config: &Config{
				Mode: TLSModePassthrough,
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

func TestCertificateConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *CertificateConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "certificate configuration is nil",
		},
		{
			name: "valid file source",
			config: &CertificateConfig{
				Source:   CertificateSourceFile,
				CertFile: "/path/to/cert.pem",
				KeyFile:  "/path/to/key.pem",
			},
			wantErr: false,
		},
		{
			name: "file source without cert file",
			config: &CertificateConfig{
				Source:  CertificateSourceFile,
				KeyFile: "/path/to/key.pem",
			},
			wantErr: true,
			errMsg:  "certificate file path required",
		},
		{
			name: "file source without key file",
			config: &CertificateConfig{
				Source:   CertificateSourceFile,
				CertFile: "/path/to/cert.pem",
			},
			wantErr: true,
			errMsg:  "key file path required",
		},
		{
			name: "valid inline source",
			config: &CertificateConfig{
				Source:   CertificateSourceInline,
				CertData: "-----BEGIN CERTIFICATE-----\n...",
				KeyData:  "-----BEGIN PRIVATE KEY-----\n...",
			},
			wantErr: false,
		},
		{
			name: "inline source without cert data",
			config: &CertificateConfig{
				Source:  CertificateSourceInline,
				KeyData: "-----BEGIN PRIVATE KEY-----\n...",
			},
			wantErr: true,
			errMsg:  "certificate data required",
		},
		{
			name: "invalid source",
			config: &CertificateConfig{
				Source: CertificateSource("invalid"),
			},
			wantErr: true,
			errMsg:  "invalid certificate source",
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

func TestClientValidationConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ClientValidationConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled",
			config: &ClientValidationConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled with CA file",
			config: &ClientValidationConfig{
				Enabled: true,
				CAFile:  "/path/to/ca.pem",
			},
			wantErr: false,
		},
		{
			name: "enabled with CA data",
			config: &ClientValidationConfig{
				Enabled: true,
				CAData:  "-----BEGIN CERTIFICATE-----\n...",
			},
			wantErr: false,
		},
		{
			name: "enabled without CA",
			config: &ClientValidationConfig{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "CA file or CA data required",
		},
		{
			name: "negative verify depth",
			config: &ClientValidationConfig{
				Enabled:     true,
				CAFile:      "/path/to/ca.pem",
				VerifyDepth: -1,
			},
			wantErr: true,
			errMsg:  "verify depth cannot be negative",
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

func TestVaultTLSConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *VaultTLSConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled",
			config: &VaultTLSConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid config",
			config: &VaultTLSConfig{
				Enabled:     true,
				PKIMount:    "pki",
				Role:        "my-role",
				CommonName:  "example.com",
				TTL:         24 * time.Hour,
				RenewBefore: 1 * time.Hour,
			},
			wantErr: false,
		},
		{
			name: "missing PKI mount",
			config: &VaultTLSConfig{
				Enabled:    true,
				Role:       "my-role",
				CommonName: "example.com",
			},
			wantErr: true,
			errMsg:  "PKI mount path required",
		},
		{
			name: "missing role",
			config: &VaultTLSConfig{
				Enabled:    true,
				PKIMount:   "pki",
				CommonName: "example.com",
			},
			wantErr: true,
			errMsg:  "PKI role name required",
		},
		{
			name: "missing common name",
			config: &VaultTLSConfig{
				Enabled:  true,
				PKIMount: "pki",
				Role:     "my-role",
			},
			wantErr: true,
			errMsg:  "common name required",
		},
		{
			name: "renewBefore >= TTL",
			config: &VaultTLSConfig{
				Enabled:     true,
				PKIMount:    "pki",
				Role:        "my-role",
				CommonName:  "example.com",
				TTL:         1 * time.Hour,
				RenewBefore: 2 * time.Hour,
			},
			wantErr: true,
			errMsg:  "renewBefore must be less than TTL",
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

func TestCertificateConfig_GetEffectiveSource(t *testing.T) {
	tests := []struct {
		name     string
		config   *CertificateConfig
		expected CertificateSource
	}{
		{
			name: "explicit file source",
			config: &CertificateConfig{
				Source: CertificateSourceFile,
			},
			expected: CertificateSourceFile,
		},
		{
			name: "explicit inline source",
			config: &CertificateConfig{
				Source: CertificateSourceInline,
			},
			expected: CertificateSourceInline,
		},
		{
			name: "inferred inline from cert data",
			config: &CertificateConfig{
				CertData: "cert data",
			},
			expected: CertificateSourceInline,
		},
		{
			name: "inferred inline from key data",
			config: &CertificateConfig{
				KeyData: "key data",
			},
			expected: CertificateSourceInline,
		},
		{
			name:     "default to file",
			config:   &CertificateConfig{},
			expected: CertificateSourceFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.config.GetEffectiveSource())
		})
	}
}

func TestConfig_Clone(t *testing.T) {
	original := &Config{
		Mode:         TLSModeMutual,
		MinVersion:   TLSVersion12,
		MaxVersion:   TLSVersion13,
		CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
		ALPN:         []string{"h2", "http/1.1"},
		ServerCertificate: &CertificateConfig{
			Source:   CertificateSourceFile,
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		ClientValidation: &ClientValidationConfig{
			Enabled:    true,
			CAFile:     "/path/to/ca.pem",
			AllowedCNs: []string{"client.example.com"},
		},
		Vault: &VaultTLSConfig{
			Enabled:  true,
			PKIMount: "pki",
			Role:     "my-role",
			AltNames: []string{"alt1.example.com"},
		},
	}

	clone := original.Clone()

	// Verify values are equal
	assert.Equal(t, original.Mode, clone.Mode)
	assert.Equal(t, original.MinVersion, clone.MinVersion)
	assert.Equal(t, original.CipherSuites, clone.CipherSuites)
	assert.Equal(t, original.ServerCertificate.CertFile, clone.ServerCertificate.CertFile)
	assert.Equal(t, original.ClientValidation.AllowedCNs, clone.ClientValidation.AllowedCNs)
	assert.Equal(t, original.Vault.AltNames, clone.Vault.AltNames)

	// Verify slices are independent
	clone.CipherSuites[0] = "modified"
	assert.NotEqual(t, original.CipherSuites[0], clone.CipherSuites[0])

	clone.ClientValidation.AllowedCNs[0] = "modified"
	assert.NotEqual(t, original.ClientValidation.AllowedCNs[0], clone.ClientValidation.AllowedCNs[0])
}

func TestConfig_Clone_Nil(t *testing.T) {
	var cfg *Config
	assert.Nil(t, cfg.Clone())
}

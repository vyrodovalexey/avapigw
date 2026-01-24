package mtls

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

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
			name: "disabled config",
			config: &Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled without CA source",
			config: &Config{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "at least one CA source must be configured",
		},
		{
			name: "enabled with CA file",
			config: &Config{
				Enabled: true,
				CAFile:  "/path/to/ca.crt",
			},
			wantErr: false,
		},
		{
			name: "enabled with CA cert",
			config: &Config{
				Enabled: true,
				CACert:  "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
			},
			wantErr: false,
		},
		{
			name: "enabled with Vault",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled:  true,
					PKIMount: "pki",
				},
			},
			wantErr: false,
		},
		{
			name: "invalid identity extraction config",
			config: &Config{
				Enabled: true,
				CACert:  "cert",
				ExtractIdentity: &IdentityExtractionConfig{
					SubjectField: "INVALID",
				},
			},
			wantErr: true,
			errMsg:  "extractIdentity",
		},
		{
			name: "invalid revocation config",
			config: &Config{
				Enabled: true,
				CACert:  "cert",
				Revocation: &RevocationConfig{
					Enabled: true,
					// Neither CRL nor OCSP enabled
				},
			},
			wantErr: true,
			errMsg:  "revocation",
		},
		{
			name: "invalid Vault config",
			config: &Config{
				Enabled: true,
				Vault: &VaultConfig{
					Enabled: true,
					// Missing PKIMount
				},
			},
			wantErr: true,
			errMsg:  "vault",
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

func TestConfig_hasCASource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{
			name:   "no CA source",
			config: &Config{},
			want:   false,
		},
		{
			name: "CA file",
			config: &Config{
				CAFile: "/path/to/ca.crt",
			},
			want: true,
		},
		{
			name: "CA cert",
			config: &Config{
				CACert: "cert-data",
			},
			want: true,
		},
		{
			name: "Vault enabled",
			config: &Config{
				Vault: &VaultConfig{
					Enabled: true,
				},
			},
			want: true,
		},
		{
			name: "Vault disabled",
			config: &Config{
				Vault: &VaultConfig{
					Enabled: false,
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.config.hasCASource()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIdentityExtractionConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *IdentityExtractionConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "empty config",
			config:  &IdentityExtractionConfig{},
			wantErr: false,
		},
		{
			name: "valid subject field CN",
			config: &IdentityExtractionConfig{
				SubjectField: "CN",
			},
			wantErr: false,
		},
		{
			name: "valid subject field O",
			config: &IdentityExtractionConfig{
				SubjectField: "O",
			},
			wantErr: false,
		},
		{
			name: "valid subject field OU",
			config: &IdentityExtractionConfig{
				SubjectField: "OU",
			},
			wantErr: false,
		},
		{
			name: "valid subject field C",
			config: &IdentityExtractionConfig{
				SubjectField: "C",
			},
			wantErr: false,
		},
		{
			name: "valid subject field ST",
			config: &IdentityExtractionConfig{
				SubjectField: "ST",
			},
			wantErr: false,
		},
		{
			name: "valid subject field L",
			config: &IdentityExtractionConfig{
				SubjectField: "L",
			},
			wantErr: false,
		},
		{
			name: "invalid subject field",
			config: &IdentityExtractionConfig{
				SubjectField: "INVALID",
			},
			wantErr: true,
			errMsg:  "invalid subject field",
		},
		{
			name: "all boolean fields enabled",
			config: &IdentityExtractionConfig{
				SubjectDN: true,
				SANDNS:    true,
				SANURI:    true,
				SANEmail:  true,
				SPIFFE:    true,
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

func TestRevocationConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *RevocationConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &RevocationConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled without methods",
			config: &RevocationConfig{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "at least one revocation method",
		},
		{
			name: "enabled with CRL",
			config: &RevocationConfig{
				Enabled: true,
				CRL: &CRLConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "enabled with OCSP",
			config: &RevocationConfig{
				Enabled: true,
				OCSP: &OCSPConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "enabled with both CRL and OCSP",
			config: &RevocationConfig{
				Enabled: true,
				CRL: &CRLConfig{
					Enabled: true,
				},
				OCSP: &OCSPConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "CRL disabled, OCSP disabled",
			config: &RevocationConfig{
				Enabled: true,
				CRL: &CRLConfig{
					Enabled: false,
				},
				OCSP: &OCSPConfig{
					Enabled: false,
				},
			},
			wantErr: true,
			errMsg:  "at least one revocation method",
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

func TestVaultConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  *VaultConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: false,
		},
		{
			name: "disabled config",
			config: &VaultConfig{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled without PKIMount",
			config: &VaultConfig{
				Enabled: true,
			},
			wantErr: true,
			errMsg:  "pkiMount is required",
		},
		{
			name: "enabled with PKIMount",
			config: &VaultConfig{
				Enabled:  true,
				PKIMount: "pki",
			},
			wantErr: false,
		},
		{
			name: "enabled with PKIMount and Role",
			config: &VaultConfig{
				Enabled:  true,
				PKIMount: "pki",
				Role:     "my-role",
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

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
	assert.True(t, config.RequireClientCert)
	assert.NotNil(t, config.ExtractIdentity)
	assert.True(t, config.ExtractIdentity.SubjectDN)
	assert.True(t, config.ExtractIdentity.SPIFFE)
}

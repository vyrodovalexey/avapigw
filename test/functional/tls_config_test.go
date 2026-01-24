//go:build functional
// +build functional

package functional

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/tls"
	"github.com/vyrodovalexey/avapigw/test/helpers"
)

func TestFunctional_TLS_Config_LoadValid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		config *tls.Config
	}{
		{
			name: "default config with certificate",
			config: func() *tls.Config {
				cfg := tls.DefaultConfig()
				cfg.ServerCertificate = &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				}
				return cfg
			}(),
		},
		{
			name: "simple mode with file source",
			config: &tls.Config{
				Mode:       tls.TLSModeSimple,
				MinVersion: tls.TLSVersion12,
				MaxVersion: tls.TLSVersion13,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
		},
		{
			name: "mutual mode with client validation",
			config: &tls.Config{
				Mode:       tls.TLSModeMutual,
				MinVersion: tls.TLSVersion12,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
				ClientValidation: &tls.ClientValidationConfig{
					Enabled:           true,
					CAFile:            "/path/to/ca.pem",
					RequireClientCert: true,
				},
			},
		},
		{
			name: "optional mutual mode",
			config: &tls.Config{
				Mode:       tls.TLSModeOptionalMutual,
				MinVersion: tls.TLSVersion12,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
				ClientValidation: &tls.ClientValidationConfig{
					Enabled: true,
					CAFile:  "/path/to/ca.pem",
				},
			},
		},
		{
			name: "inline certificate source",
			config: &tls.Config{
				Mode:       tls.TLSModeSimple,
				MinVersion: tls.TLSVersion12,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceInline,
					CertData: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					KeyData:  "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
				},
			},
		},
		{
			name: "passthrough mode",
			config: &tls.Config{
				Mode: tls.TLSModePassthrough,
			},
		},
		{
			name: "insecure mode",
			config: &tls.Config{
				Mode: tls.TLSModeInsecure,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate()
			assert.NoError(t, err)
		})
	}
}

func TestFunctional_TLS_Config_LoadInvalid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		config      *tls.Config
		expectedErr string
	}{
		{
			name: "invalid mode",
			config: &tls.Config{
				Mode: "INVALID_MODE",
			},
			expectedErr: "invalid TLS mode",
		},
		{
			name: "invalid min version",
			config: &tls.Config{
				Mode:       tls.TLSModeSimple,
				MinVersion: "INVALID",
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expectedErr: "invalid TLS version",
		},
		{
			name: "invalid max version",
			config: &tls.Config{
				Mode:       tls.TLSModeSimple,
				MaxVersion: "INVALID",
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expectedErr: "invalid TLS version",
		},
		{
			name: "min version greater than max version",
			config: &tls.Config{
				Mode:       tls.TLSModeSimple,
				MinVersion: tls.TLSVersion13,
				MaxVersion: tls.TLSVersion12,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expectedErr: "minVersion",
		},
		{
			name: "simple mode without certificate",
			config: &tls.Config{
				Mode: tls.TLSModeSimple,
			},
			expectedErr: "server certificate required",
		},
		{
			name: "mutual mode without client validation",
			config: &tls.Config{
				Mode: tls.TLSModeMutual,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
			},
			expectedErr: "client validation required",
		},
		{
			name: "file source without cert file",
			config: &tls.Config{
				Mode: tls.TLSModeSimple,
				ServerCertificate: &tls.CertificateConfig{
					Source:  tls.CertificateSourceFile,
					KeyFile: "/path/to/key.pem",
				},
			},
			expectedErr: "certificate file path required",
		},
		{
			name: "file source without key file",
			config: &tls.Config{
				Mode: tls.TLSModeSimple,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
				},
			},
			expectedErr: "key file path required",
		},
		{
			name: "inline source without cert data",
			config: &tls.Config{
				Mode: tls.TLSModeSimple,
				ServerCertificate: &tls.CertificateConfig{
					Source:  tls.CertificateSourceInline,
					KeyData: "key-data",
				},
			},
			expectedErr: "certificate data required",
		},
		{
			name: "inline source without key data",
			config: &tls.Config{
				Mode: tls.TLSModeSimple,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceInline,
					CertData: "cert-data",
				},
			},
			expectedErr: "key data required",
		},
		{
			name: "client validation without CA",
			config: &tls.Config{
				Mode: tls.TLSModeMutual,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
				ClientValidation: &tls.ClientValidationConfig{
					Enabled: true,
				},
			},
			expectedErr: "CA file or CA data required",
		},
		{
			name: "negative verify depth",
			config: &tls.Config{
				Mode: tls.TLSModeMutual,
				ServerCertificate: &tls.CertificateConfig{
					Source:   tls.CertificateSourceFile,
					CertFile: "/path/to/cert.pem",
					KeyFile:  "/path/to/key.pem",
				},
				ClientValidation: &tls.ClientValidationConfig{
					Enabled:     true,
					CAFile:      "/path/to/ca.pem",
					VerifyDepth: -1,
				},
			},
			expectedErr: "verify depth cannot be negative",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}

func TestFunctional_TLS_Config_Defaults(t *testing.T) {
	t.Parallel()

	cfg := tls.DefaultConfig()

	assert.Equal(t, tls.TLSModeSimple, cfg.Mode)
	assert.Equal(t, tls.TLSVersion12, cfg.MinVersion)
	assert.Equal(t, tls.TLSVersion13, cfg.MaxVersion)
	assert.Contains(t, cfg.ALPN, "h2")
	assert.Contains(t, cfg.ALPN, "http/1.1")
}

func TestFunctional_TLS_Config_Modes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		mode                tls.TLSMode
		valid               bool
		requiresCertificate bool
		requiresClientCA    bool
	}{
		{tls.TLSModeSimple, true, true, false},
		{tls.TLSModeMutual, true, true, true},
		{tls.TLSModeOptionalMutual, true, true, true},
		{tls.TLSModePassthrough, true, false, false},
		{tls.TLSModeAutoPassthrough, true, false, false},
		{tls.TLSModeInsecure, true, false, false},
		{"INVALID", false, false, false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, tc.mode.IsValid())
			assert.Equal(t, tc.requiresCertificate, tc.mode.RequiresCertificate())
			assert.Equal(t, tc.requiresClientCA, tc.mode.RequiresClientCA())
		})
	}
}

func TestFunctional_TLS_Config_CipherSuites(t *testing.T) {
	t.Parallel()

	t.Run("default secure cipher suites", func(t *testing.T) {
		t.Parallel()
		suites := tls.DefaultSecureCipherSuites()
		assert.NotEmpty(t, suites)
	})

	t.Run("default secure cipher suite names", func(t *testing.T) {
		t.Parallel()
		names := tls.DefaultSecureCipherSuiteNames()
		assert.NotEmpty(t, names)
		assert.Contains(t, names, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
	})

	t.Run("FIPS cipher suites", func(t *testing.T) {
		t.Parallel()
		suites := tls.FIPSCipherSuites()
		assert.NotEmpty(t, suites)
	})

	t.Run("parse valid cipher suites", func(t *testing.T) {
		t.Parallel()
		names := []string{
			"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
			"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		}
		suites, err := tls.ParseCipherSuites(names)
		require.NoError(t, err)
		assert.Len(t, suites, 2)
	})

	t.Run("parse invalid cipher suite", func(t *testing.T) {
		t.Parallel()
		names := []string{"INVALID_CIPHER_SUITE"}
		_, err := tls.ParseCipherSuites(names)
		require.Error(t, err)
	})

	t.Run("validate cipher suites", func(t *testing.T) {
		t.Parallel()
		validNames := []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"}
		err := tls.ValidateCipherSuites(validNames)
		assert.NoError(t, err)

		invalidNames := []string{"INVALID"}
		err = tls.ValidateCipherSuites(invalidNames)
		assert.Error(t, err)
	})

	t.Run("get cipher suite info", func(t *testing.T) {
		t.Parallel()
		suite, ok := tls.GetCipherSuiteInfo("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
		assert.True(t, ok)
		assert.True(t, suite.Secure)
		assert.True(t, suite.FIPS)

		_, ok = tls.GetCipherSuiteInfo("INVALID")
		assert.False(t, ok)
	})

	t.Run("is secure cipher suite", func(t *testing.T) {
		t.Parallel()
		suites := tls.DefaultSecureCipherSuites()
		for _, id := range suites {
			assert.True(t, tls.IsSecureCipherSuite(id))
		}
	})
}

func TestFunctional_TLS_Config_Versions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		version  tls.TLSVersion
		valid    bool
		isLegacy bool
	}{
		{tls.TLSVersionAuto, true, false},
		{tls.TLSVersion10, true, true},
		{tls.TLSVersion11, true, true},
		{tls.TLSVersion12, true, false},
		{tls.TLSVersion13, true, false},
		{"INVALID", false, false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(string(tc.version), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, tc.version.IsValid())
			assert.Equal(t, tc.isLegacy, tc.version.IsLegacy())
		})
	}

	t.Run("version to TLS version", func(t *testing.T) {
		t.Parallel()
		assert.NotZero(t, tls.TLSVersion12.ToTLSVersion())
		assert.NotZero(t, tls.TLSVersion13.ToTLSVersion())
		assert.Zero(t, tls.TLSVersionAuto.ToTLSVersion())
	})
}

func TestFunctional_TLS_Config_CertificatePaths(t *testing.T) {
	t.Parallel()

	// Generate test certificates
	certs, err := helpers.GenerateTestCertificates()
	require.NoError(t, err)
	require.NoError(t, certs.WriteToFiles())
	defer certs.Cleanup()

	t.Run("valid certificate paths", func(t *testing.T) {
		cfg := &tls.Config{
			Mode:       tls.TLSModeSimple,
			MinVersion: tls.TLSVersion12,
			ServerCertificate: &tls.CertificateConfig{
				Source:   tls.CertificateSourceFile,
				CertFile: certs.ServerCertPath(),
				KeyFile:  certs.ServerKeyPath(),
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("mutual TLS with CA path", func(t *testing.T) {
		cfg := &tls.Config{
			Mode:       tls.TLSModeMutual,
			MinVersion: tls.TLSVersion12,
			ServerCertificate: &tls.CertificateConfig{
				Source:   tls.CertificateSourceFile,
				CertFile: certs.ServerCertPath(),
				KeyFile:  certs.ServerKeyPath(),
			},
			ClientValidation: &tls.ClientValidationConfig{
				Enabled:           true,
				CAFile:            certs.CACertPath(),
				RequireClientCert: true,
			},
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

func TestFunctional_TLS_Config_Clone(t *testing.T) {
	t.Parallel()

	original := &tls.Config{
		Mode:         tls.TLSModeMutual,
		MinVersion:   tls.TLSVersion12,
		MaxVersion:   tls.TLSVersion13,
		CipherSuites: []string{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
		ALPN:         []string{"h2", "http/1.1"},
		ServerCertificate: &tls.CertificateConfig{
			Source:   tls.CertificateSourceFile,
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
		ClientValidation: &tls.ClientValidationConfig{
			Enabled:    true,
			CAFile:     "/path/to/ca.pem",
			AllowedCNs: []string{"client1", "client2"},
		},
		Vault: &tls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
			AltNames:   []string{"alt1.local", "alt2.local"},
			TTL:        24 * time.Hour,
		},
	}

	clone := original.Clone()

	// Verify clone is not nil
	require.NotNil(t, clone)

	// Verify values are equal
	assert.Equal(t, original.Mode, clone.Mode)
	assert.Equal(t, original.MinVersion, clone.MinVersion)
	assert.Equal(t, original.MaxVersion, clone.MaxVersion)
	assert.Equal(t, original.CipherSuites, clone.CipherSuites)
	assert.Equal(t, original.ALPN, clone.ALPN)

	// Verify nested objects are cloned
	assert.NotSame(t, original.ServerCertificate, clone.ServerCertificate)
	assert.Equal(t, original.ServerCertificate.CertFile, clone.ServerCertificate.CertFile)

	assert.NotSame(t, original.ClientValidation, clone.ClientValidation)
	assert.Equal(t, original.ClientValidation.AllowedCNs, clone.ClientValidation.AllowedCNs)

	assert.NotSame(t, original.Vault, clone.Vault)
	assert.Equal(t, original.Vault.AltNames, clone.Vault.AltNames)

	// Verify modifying clone doesn't affect original
	clone.Mode = tls.TLSModeSimple
	assert.NotEqual(t, original.Mode, clone.Mode)

	clone.CipherSuites[0] = "MODIFIED"
	assert.NotEqual(t, original.CipherSuites[0], clone.CipherSuites[0])
}

func TestFunctional_TLS_Config_VaultTLS(t *testing.T) {
	t.Parallel()

	t.Run("valid vault config", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled:     true,
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			AltNames:    []string{"alt.local"},
			TTL:         24 * time.Hour,
			RenewBefore: 1 * time.Hour,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("disabled vault config", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled: false,
		}
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing PKI mount", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled:    true,
			Role:       "test-role",
			CommonName: "test.local",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PKI mount")
	})

	t.Run("missing role", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			CommonName: "test.local",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "role")
	})

	t.Run("missing common name", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled:  true,
			PKIMount: "pki",
			Role:     "test-role",
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "common name")
	})

	t.Run("negative TTL", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled:    true,
			PKIMount:   "pki",
			Role:       "test-role",
			CommonName: "test.local",
			TTL:        -1 * time.Hour,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TTL")
	})

	t.Run("renewBefore greater than TTL", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.VaultTLSConfig{
			Enabled:     true,
			PKIMount:    "pki",
			Role:        "test-role",
			CommonName:  "test.local",
			TTL:         1 * time.Hour,
			RenewBefore: 2 * time.Hour,
		}
		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "renewBefore")
	})
}

func TestFunctional_TLS_Config_CertificateSource(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		source tls.CertificateSource
		valid  bool
	}{
		{tls.CertificateSourceFile, true},
		{tls.CertificateSourceInline, true},
		{tls.CertificateSourceVault, true},
		{"invalid", false},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(string(tc.source), func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.valid, tc.source.IsValid())
		})
	}
}

func TestFunctional_TLS_Config_GetEffectiveSource(t *testing.T) {
	t.Parallel()

	t.Run("explicit file source", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.CertificateConfig{
			Source:   tls.CertificateSourceFile,
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		}
		assert.Equal(t, tls.CertificateSourceFile, cfg.GetEffectiveSource())
	})

	t.Run("explicit inline source", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.CertificateConfig{
			Source:   tls.CertificateSourceInline,
			CertData: "cert-data",
			KeyData:  "key-data",
		}
		assert.Equal(t, tls.CertificateSourceInline, cfg.GetEffectiveSource())
	})

	t.Run("inferred inline source", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.CertificateConfig{
			CertData: "cert-data",
			KeyData:  "key-data",
		}
		assert.Equal(t, tls.CertificateSourceInline, cfg.GetEffectiveSource())
	})

	t.Run("default to file source", func(t *testing.T) {
		t.Parallel()
		cfg := &tls.CertificateConfig{
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		}
		assert.Equal(t, tls.CertificateSourceFile, cfg.GetEffectiveSource())
	})
}

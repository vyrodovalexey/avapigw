package cert

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratorConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *GeneratorConfig
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			config: &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         365 * 24 * time.Hour,
				KeySize:          2048,
			},
			wantErr: false,
		},
		{
			name: "missing service name",
			config: &GeneratorConfig{
				ServiceNamespace: "default",
				Validity:         365 * 24 * time.Hour,
			},
			wantErr: true,
			errMsg:  "service name is required",
		},
		{
			name: "missing service namespace",
			config: &GeneratorConfig{
				ServiceName: "webhook-service",
				Validity:    365 * 24 * time.Hour,
			},
			wantErr: true,
			errMsg:  "service namespace is required",
		},
		{
			name: "zero validity",
			config: &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         0,
			},
			wantErr: true,
			errMsg:  "validity must be positive",
		},
		{
			name: "negative validity",
			config: &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         -1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "validity must be positive",
		},
		{
			name: "key size too small",
			config: &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         365 * 24 * time.Hour,
				KeySize:          1024,
			},
			wantErr: true,
			errMsg:  "key size must be at least 2048",
		},
		{
			name: "key size zero uses default",
			config: &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         365 * 24 * time.Hour,
				KeySize:          0, // Should be valid, uses default
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

func TestNewGenerator(t *testing.T) {
	t.Run("with defaults", func(t *testing.T) {
		cfg := &GeneratorConfig{
			ServiceName:      "webhook-service",
			ServiceNamespace: "default",
		}
		generator := NewGenerator(cfg)
		assert.NotNil(t, generator)
		assert.Equal(t, DefaultKeySize, generator.config.KeySize)
		assert.Equal(t, DefaultValidity, generator.config.Validity)
	})

	t.Run("with custom values", func(t *testing.T) {
		cfg := &GeneratorConfig{
			ServiceName:      "webhook-service",
			ServiceNamespace: "default",
			Validity:         30 * 24 * time.Hour,
			KeySize:          4096,
		}
		generator := NewGenerator(cfg)
		assert.NotNil(t, generator)
		assert.Equal(t, 4096, generator.config.KeySize)
		assert.Equal(t, 30*24*time.Hour, generator.config.Validity)
	})
}

func TestGenerator_GenerateCA(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(cfg)

	caCertPEM, caKeyPEM, err := generator.GenerateCA()
	require.NoError(t, err)
	assert.NotEmpty(t, caCertPEM)
	assert.NotEmpty(t, caKeyPEM)

	// Parse and verify CA certificate
	caCert, err := ParseCertificate(caCertPEM)
	require.NoError(t, err)
	assert.True(t, caCert.IsCA)
	assert.Equal(t, CACommonName, caCert.Subject.CommonName)
	assert.Contains(t, caCert.Subject.Organization, CAOrganization)
	assert.True(t, caCert.NotAfter.After(time.Now()))
	assert.True(t, caCert.NotBefore.Before(time.Now().Add(time.Minute)))

	// Verify key usage
	assert.True(t, caCert.KeyUsage&x509.KeyUsageCertSign != 0)
	assert.True(t, caCert.KeyUsage&x509.KeyUsageCRLSign != 0)
	assert.True(t, caCert.KeyUsage&x509.KeyUsageDigitalSignature != 0)
}

func TestGenerator_GenerateServerCert(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
		DNSNames:         []string{"extra.example.com"},
	}
	generator := NewGenerator(cfg)

	// First generate CA
	caCertPEM, caKeyPEM, err := generator.GenerateCA()
	require.NoError(t, err)

	// Generate server certificate
	serverCertPEM, serverKeyPEM, expiresAt, err := generator.GenerateServerCert(caCertPEM, caKeyPEM)
	require.NoError(t, err)
	assert.NotEmpty(t, serverCertPEM)
	assert.NotEmpty(t, serverKeyPEM)
	assert.True(t, expiresAt.After(time.Now()))

	// Parse and verify server certificate
	serverCert, err := ParseCertificate(serverCertPEM)
	require.NoError(t, err)
	assert.False(t, serverCert.IsCA)
	assert.Equal(t, "webhook-service", serverCert.Subject.CommonName)

	// Verify DNS names
	expectedDNSNames := []string{
		"webhook-service",
		"webhook-service.default",
		"webhook-service.default.svc",
		"webhook-service.default.svc.cluster.local",
		"extra.example.com",
	}
	for _, dns := range expectedDNSNames {
		assert.Contains(t, serverCert.DNSNames, dns)
	}

	// Verify key usage
	assert.True(t, serverCert.KeyUsage&x509.KeyUsageDigitalSignature != 0)
	assert.True(t, serverCert.KeyUsage&x509.KeyUsageKeyEncipherment != 0)
	assert.Contains(t, serverCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// Verify certificate chain
	caCert, err := ParseCertificate(caCertPEM)
	require.NoError(t, err)
	err = serverCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

func TestGenerator_GenerateServerCert_InvalidCA(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(cfg)

	// Test with invalid CA cert
	_, _, _, err := generator.GenerateServerCert([]byte("invalid"), []byte("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA certificate")

	// Generate valid CA cert but invalid key
	caCertPEM, _, err := generator.GenerateCA()
	require.NoError(t, err)

	_, _, _, err = generator.GenerateServerCert(caCertPEM, []byte("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CA private key")
}

func TestGenerator_Generate(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(cfg)

	bundle, err := generator.Generate()
	require.NoError(t, err)
	assert.NotNil(t, bundle)
	assert.NotEmpty(t, bundle.CACert)
	assert.NotEmpty(t, bundle.CAKey)
	assert.NotEmpty(t, bundle.ServerCert)
	assert.NotEmpty(t, bundle.ServerKey)
	assert.True(t, bundle.ExpiresAt.After(time.Now()))

	// Verify CA certificate
	caCert, err := ParseCertificate(bundle.CACert)
	require.NoError(t, err)
	assert.True(t, caCert.IsCA)

	// Verify server certificate
	serverCert, err := ParseCertificate(bundle.ServerCert)
	require.NoError(t, err)
	assert.False(t, serverCert.IsCA)

	// Verify server cert is signed by CA
	err = serverCert.CheckSignatureFrom(caCert)
	assert.NoError(t, err)
}

func TestNeedsRotation(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         30 * 24 * time.Hour, // 30 days
		KeySize:          2048,
	}
	generator := NewGenerator(cfg)

	bundle, err := generator.Generate()
	require.NoError(t, err)

	tests := []struct {
		name              string
		rotationThreshold time.Duration
		expectRotation    bool
	}{
		{
			name:              "no rotation needed - threshold less than validity",
			rotationThreshold: 7 * 24 * time.Hour, // 7 days
			expectRotation:    false,
		},
		{
			name:              "rotation needed - threshold greater than validity",
			rotationThreshold: 60 * 24 * time.Hour, // 60 days (more than cert validity)
			expectRotation:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			needsRotation, err := NeedsRotation(bundle.ServerCert, tt.rotationThreshold)
			require.NoError(t, err)
			assert.Equal(t, tt.expectRotation, needsRotation)
		})
	}
}

func TestNeedsRotation_InvalidCert(t *testing.T) {
	_, err := NeedsRotation([]byte("invalid"), 24*time.Hour)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

func TestParseCertificate(t *testing.T) {
	t.Run("valid certificate", func(t *testing.T) {
		cfg := &GeneratorConfig{
			ServiceName:      "webhook-service",
			ServiceNamespace: "default",
			Validity:         365 * 24 * time.Hour,
		}
		generator := NewGenerator(cfg)
		caCertPEM, _, err := generator.GenerateCA()
		require.NoError(t, err)

		cert, err := ParseCertificate(caCertPEM)
		require.NoError(t, err)
		assert.NotNil(t, cert)
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := ParseCertificate([]byte("not a pem"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("wrong PEM type", func(t *testing.T) {
		wrongPEM := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBALRiMLAHudeSA2ai
-----END RSA PRIVATE KEY-----`)
		_, err := ParseCertificate(wrongPEM)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected CERTIFICATE PEM block")
	})
}

func TestGetCertificateExpiry(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(cfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	expiry, err := GetCertificateExpiry(bundle.ServerCert)
	require.NoError(t, err)
	assert.True(t, expiry.After(time.Now()))
	assert.True(t, expiry.Before(time.Now().Add(366*24*time.Hour)))
}

func TestGetCertificateExpiry_InvalidCert(t *testing.T) {
	_, err := GetCertificateExpiry([]byte("invalid"))
	assert.Error(t, err)
}

func TestIsCertificateValid(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(cfg)
	bundle, err := generator.Generate()
	require.NoError(t, err)

	valid, err := IsCertificateValid(bundle.ServerCert)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestIsCertificateValid_InvalidCert(t *testing.T) {
	_, err := IsCertificateValid([]byte("invalid"))
	assert.Error(t, err)
}

func TestBuildDNSNames(t *testing.T) {
	tests := []struct {
		name             string
		serviceName      string
		serviceNamespace string
		additionalDNS    []string
		expectedDNS      []string
	}{
		{
			name:             "basic DNS names",
			serviceName:      "webhook",
			serviceNamespace: "default",
			additionalDNS:    nil,
			expectedDNS: []string{
				"webhook",
				"webhook.default",
				"webhook.default.svc",
				"webhook.default.svc.cluster.local",
			},
		},
		{
			name:             "with additional DNS names",
			serviceName:      "webhook",
			serviceNamespace: "kube-system",
			additionalDNS:    []string{"webhook.example.com", "api.example.com"},
			expectedDNS: []string{
				"webhook",
				"webhook.kube-system",
				"webhook.kube-system.svc",
				"webhook.kube-system.svc.cluster.local",
				"webhook.example.com",
				"api.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &GeneratorConfig{
				ServiceName:      tt.serviceName,
				ServiceNamespace: tt.serviceNamespace,
				DNSNames:         tt.additionalDNS,
				Validity:         365 * 24 * time.Hour,
			}
			generator := NewGenerator(cfg)
			dnsNames := generator.buildDNSNames()

			for _, expected := range tt.expectedDNS {
				assert.Contains(t, dnsNames, expected)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 2048, DefaultKeySize)
	assert.Equal(t, 365*24*time.Hour, DefaultValidity)
	assert.Equal(t, 30*24*time.Hour, DefaultRotationThreshold)
	assert.Equal(t, "avapigw-webhook-ca", CACommonName)
	assert.Equal(t, "avapigw", CAOrganization)
}

func TestParsePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		keyPEM  []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "invalid PEM",
			keyPEM:  []byte("not a pem"),
			wantErr: true,
			errMsg:  "failed to decode PEM block",
		},
		{
			name: "wrong PEM type",
			keyPEM: []byte(`-----BEGIN CERTIFICATE-----
MIIBOgIBAAJBALRiMLAHudeSA2ai
-----END CERTIFICATE-----`),
			wantErr: true,
			errMsg:  "expected RSA PRIVATE KEY PEM block",
		},
		{
			name: "invalid key data",
			keyPEM: []byte(`-----BEGIN RSA PRIVATE KEY-----
aW52YWxpZGtleWRhdGE=
-----END RSA PRIVATE KEY-----`),
			wantErr: true,
			errMsg:  "failed to parse private key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePrivateKey(tt.keyPEM)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestParsePrivateKey_ValidKey(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
	}
	generator := NewGenerator(cfg)

	_, caKeyPEM, err := generator.GenerateCA()
	require.NoError(t, err)

	key, err := parsePrivateKey(caKeyPEM)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestParseCertificate_InvalidCertData(t *testing.T) {
	// Test with valid PEM structure but invalid certificate data
	invalidCertPEM := []byte(`-----BEGIN CERTIFICATE-----
aW52YWxpZGNlcnRkYXRh
-----END CERTIFICATE-----`)

	_, err := ParseCertificate(invalidCertPEM)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

func TestCertificateBundle_Fields(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(cfg)

	bundle, err := generator.Generate()
	require.NoError(t, err)

	// Verify all fields are populated
	assert.NotEmpty(t, bundle.CACert, "CACert should not be empty")
	assert.NotEmpty(t, bundle.CAKey, "CAKey should not be empty")
	assert.NotEmpty(t, bundle.ServerCert, "ServerCert should not be empty")
	assert.NotEmpty(t, bundle.ServerKey, "ServerKey should not be empty")
	assert.False(t, bundle.ExpiresAt.IsZero(), "ExpiresAt should not be zero")

	// Verify expiry is in the future
	assert.True(t, bundle.ExpiresAt.After(time.Now()))
}

func TestGenerator_GenerateCA_KeyUsage(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(cfg)

	caCertPEM, _, err := generator.GenerateCA()
	require.NoError(t, err)

	caCert, err := ParseCertificate(caCertPEM)
	require.NoError(t, err)

	// Verify CA properties
	assert.True(t, caCert.IsCA)
	assert.True(t, caCert.BasicConstraintsValid)
	assert.Equal(t, 1, caCert.MaxPathLen)

	// Verify key usage flags
	expectedKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	assert.Equal(t, expectedKeyUsage, caCert.KeyUsage)
}

func TestGenerator_GenerateServerCert_KeyUsage(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
	}
	generator := NewGenerator(cfg)

	caCertPEM, caKeyPEM, err := generator.GenerateCA()
	require.NoError(t, err)

	serverCertPEM, _, _, err := generator.GenerateServerCert(caCertPEM, caKeyPEM)
	require.NoError(t, err)

	serverCert, err := ParseCertificate(serverCertPEM)
	require.NoError(t, err)

	// Verify server cert properties
	assert.False(t, serverCert.IsCA)
	assert.True(t, serverCert.BasicConstraintsValid)

	// Verify key usage flags
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	assert.Equal(t, expectedKeyUsage, serverCert.KeyUsage)

	// Verify extended key usage
	assert.Contains(t, serverCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

func TestGenerator_Generate_WithDifferentKeySizes(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{
			name:    "2048 bit key",
			keySize: 2048,
		},
		{
			name:    "4096 bit key",
			keySize: 4096,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         365 * 24 * time.Hour,
				KeySize:          tt.keySize,
			}
			generator := NewGenerator(cfg)

			bundle, err := generator.Generate()
			require.NoError(t, err)
			assert.NotNil(t, bundle)

			// Verify certificates are valid
			caCert, err := ParseCertificate(bundle.CACert)
			require.NoError(t, err)
			assert.True(t, caCert.IsCA)

			serverCert, err := ParseCertificate(bundle.ServerCert)
			require.NoError(t, err)
			assert.False(t, serverCert.IsCA)
		})
	}
}

func TestGenerator_Generate_WithDifferentValidities(t *testing.T) {
	tests := []struct {
		name     string
		validity time.Duration
	}{
		{
			name:     "1 day validity",
			validity: 24 * time.Hour,
		},
		{
			name:     "30 days validity",
			validity: 30 * 24 * time.Hour,
		},
		{
			name:     "365 days validity",
			validity: 365 * 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &GeneratorConfig{
				ServiceName:      "webhook-service",
				ServiceNamespace: "default",
				Validity:         tt.validity,
				KeySize:          2048,
			}
			generator := NewGenerator(cfg)

			bundle, err := generator.Generate()
			require.NoError(t, err)

			// Verify expiry is approximately correct
			expectedExpiry := time.Now().Add(tt.validity)
			assert.WithinDuration(t, expectedExpiry, bundle.ExpiresAt, 5*time.Second)
		})
	}
}

func TestBuildServerCertTemplate(t *testing.T) {
	cfg := &GeneratorConfig{
		ServiceName:      "webhook-service",
		ServiceNamespace: "default",
		Validity:         365 * 24 * time.Hour,
		KeySize:          2048,
		DNSNames:         []string{"extra.dns.name"},
	}
	generator := NewGenerator(cfg)

	expiresAt := time.Now().Add(cfg.Validity)
	template := generator.buildServerCertTemplate(nil, expiresAt)

	assert.Equal(t, "webhook-service", template.Subject.CommonName)
	assert.Contains(t, template.Subject.Organization, CAOrganization)
	assert.False(t, template.IsCA)
	assert.True(t, template.BasicConstraintsValid)
	assert.Equal(t, x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment, template.KeyUsage)
	assert.Contains(t, template.ExtKeyUsage, x509.ExtKeyUsageServerAuth)

	// Verify DNS names
	assert.Contains(t, template.DNSNames, "webhook-service")
	assert.Contains(t, template.DNSNames, "webhook-service.default")
	assert.Contains(t, template.DNSNames, "webhook-service.default.svc")
	assert.Contains(t, template.DNSNames, "webhook-service.default.svc.cluster.local")
	assert.Contains(t, template.DNSNames, "extra.dns.name")
}

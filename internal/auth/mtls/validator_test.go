package mtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// generateTestCA generates a test CA certificate and key.
func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	return caCert, caKey
}

// generateTestCert generates a test client certificate signed by the CA.
func generateTestCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, opts ...func(*x509.Certificate)) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:         "test-client",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"San Francisco"},
		},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:       []string{"test.example.com", "test2.example.com"},
		EmailAddresses: []string{"test@example.com"},
	}

	// Apply custom options
	for _, opt := range opts {
		opt(clientTemplate)
	}

	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	clientCert, err := x509.ParseCertificate(clientDER)
	require.NoError(t, err)

	return clientCert, clientKey
}

// generateSelfSignedCert generates a self-signed certificate (not signed by CA).
func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject: pkix.Name{
			CommonName: "self-signed",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

// newTestCAPool creates a CA pool from a certificate for testing.
func newTestCAPool(caCert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool
}

func TestNewValidator(t *testing.T) {
	t.Parallel()

	caCert, _ := generateTestCA(t)
	caPool := newTestCAPool(caCert)

	tests := []struct {
		name    string
		config  *Config
		opts    []ValidatorOption
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
			errMsg:  "config is required",
		},
		{
			name: "valid config with CA pool",
			config: &Config{
				Enabled: true,
			},
			opts: []ValidatorOption{
				WithCAPool(caPool),
			},
			wantErr: false,
		},
		{
			name: "valid config with CA cert PEM",
			config: &Config{
				Enabled: true,
				CACert:  "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl\nc3RjYTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBExDzANBgNVBAMM\nBnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC6rUOjJxYJJqHvva8bLMvh\nfNqW8S5tuqxBAGGBpNLnpnVQx2yyLahQiqdsBNeKZYGODqERYaskYNMn8GOhkgMb\nAgMBAAGjUzBRMB0GA1UdDgQWBBQK8So4HXVB2rGHveCAbLOHXTozMDAfBgNVHSME\nGDAWgBQK8So4HXVB2rGHveCAbLOHXTozMDAPBgNVHRMBAf8EBTADAQH/MA0GCSqG\nSIb3DQEBCwUAA0EAhZwN+aOzqPpSgJ3V3P5r6E3P5nHlYa3xnKy2L8WvVnPhZyZn\n2qCk3QZQ3Da3kf8O3xE3L6D8YkqMpKWDlA5ACg==\n-----END CERTIFICATE-----",
			},
			wantErr: true, // Invalid PEM will fail
		},
		{
			name: "config with CA file (not implemented)",
			config: &Config{
				Enabled: true,
				CAFile:  "/path/to/ca.crt",
			},
			wantErr: true,
			errMsg:  "CA file loading not yet implemented",
		},
		{
			name: "config with logger option",
			config: &Config{
				Enabled: true,
			},
			opts: []ValidatorOption{
				WithCAPool(caPool),
				WithValidatorLogger(observability.NopLogger()),
			},
			wantErr: false,
		},
		{
			name: "config with metrics option",
			config: &Config{
				Enabled: true,
			},
			opts: []ValidatorOption{
				WithCAPool(caPool),
				WithValidatorMetrics(NewMetrics("test")),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := NewValidator(tt.config, tt.opts...)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, v)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, v)
			}
		})
	}
}

func TestValidator_Validate(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	caPool := newTestCAPool(caCert)

	// Generate valid client certificate
	validCert, _ := generateTestCert(t, caCert, caKey)

	// Generate self-signed (untrusted) certificate
	selfSignedCert, _ := generateSelfSignedCert(t)

	// Generate certificate with SPIFFE ID
	spiffeURL, _ := url.Parse("spiffe://example.org/workload/test")
	spiffeCert, _ := generateTestCert(t, caCert, caKey, func(c *x509.Certificate) {
		c.URIs = []*url.URL{spiffeURL}
	})

	tests := []struct {
		name    string
		config  *Config
		cert    *x509.Certificate
		chain   []*x509.Certificate
		wantErr error
	}{
		{
			name: "valid certificate",
			config: &Config{
				Enabled: true,
			},
			cert:    validCert,
			chain:   nil,
			wantErr: nil,
		},
		{
			name: "nil certificate",
			config: &Config{
				Enabled: true,
			},
			cert:    nil,
			chain:   nil,
			wantErr: ErrNoCertificate,
		},
		{
			name: "untrusted certificate",
			config: &Config{
				Enabled: true,
			},
			cert:    selfSignedCert,
			chain:   nil,
			wantErr: ErrCertificateUntrusted,
		},
		{
			name: "certificate with SPIFFE ID",
			config: &Config{
				Enabled: true,
				ExtractIdentity: &IdentityExtractionConfig{
					SPIFFE: true,
				},
			},
			cert:    spiffeCert,
			chain:   nil,
			wantErr: nil,
		},
		{
			name: "certificate with revocation check (CRL)",
			config: &Config{
				Enabled: true,
				Revocation: &RevocationConfig{
					Enabled: true,
					CRL: &CRLConfig{
						Enabled: true,
					},
				},
			},
			cert:    validCert,
			chain:   nil,
			wantErr: nil,
		},
		{
			name: "certificate with revocation check (OCSP)",
			config: &Config{
				Enabled: true,
				Revocation: &RevocationConfig{
					Enabled: true,
					OCSP: &OCSPConfig{
						Enabled: true,
					},
				},
			},
			cert:    validCert,
			chain:   nil,
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := NewValidator(tt.config, WithCAPool(caPool))
			require.NoError(t, err)

			info, err := v.Validate(context.Background(), tt.cert, tt.chain)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, info)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, info)
				if tt.cert != nil {
					assert.Equal(t, tt.cert.Subject.String(), info.SubjectDN)
					assert.NotEmpty(t, info.Fingerprint)
				}
			}
		})
	}
}

func TestValidator_ValidateExpiredCertificate(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	caPool := newTestCAPool(caCert)

	// Generate expired certificate - the chain validation will catch this
	expiredCert, _ := generateTestCert(t, caCert, caKey, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})

	config := &Config{
		Enabled: true,
	}

	v, err := NewValidator(config, WithCAPool(caPool))
	require.NoError(t, err)

	info, err := v.Validate(context.Background(), expiredCert, nil)
	// The x509.Verify will catch the expiration as part of chain validation
	assert.Error(t, err)
	assert.Nil(t, info)
	// The error will be ErrCertificateUntrusted because chain validation fails first
	assert.ErrorIs(t, err, ErrCertificateUntrusted)
}

func TestValidator_ValidateNotYetValidCertificate(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	caPool := newTestCAPool(caCert)

	// Generate not-yet-valid certificate
	futureValidCert, _ := generateTestCert(t, caCert, caKey, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(24 * time.Hour)
		c.NotAfter = time.Now().Add(48 * time.Hour)
	})

	config := &Config{
		Enabled: true,
	}

	v, err := NewValidator(config, WithCAPool(caPool))
	require.NoError(t, err)

	info, err := v.Validate(context.Background(), futureValidCert, nil)
	// The x509.Verify will catch this as part of chain validation
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrCertificateUntrusted)
}

func TestValidator_ExtractInfo(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	caPool := newTestCAPool(caCert)

	// Generate certificate with various SANs
	spiffeURL, _ := url.Parse("spiffe://example.org/workload/test")
	httpURL, _ := url.Parse("https://example.com/service")

	cert, _ := generateTestCert(t, caCert, caKey, func(c *x509.Certificate) {
		c.URIs = []*url.URL{spiffeURL, httpURL}
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
	})

	config := &Config{
		Enabled: true,
		ExtractIdentity: &IdentityExtractionConfig{
			SPIFFE: true,
		},
	}

	v, err := NewValidator(config, WithCAPool(caPool))
	require.NoError(t, err)

	info, err := v.Validate(context.Background(), cert, nil)
	require.NoError(t, err)
	require.NotNil(t, info)

	// Verify extracted info
	assert.NotEmpty(t, info.SubjectDN)
	assert.NotEmpty(t, info.IssuerDN)
	assert.NotEmpty(t, info.SerialNumber)
	assert.NotEmpty(t, info.Fingerprint)
	assert.Equal(t, "spiffe://example.org/workload/test", info.SPIFFEID)
	assert.Contains(t, info.URIs, "spiffe://example.org/workload/test")
	assert.Contains(t, info.URIs, "https://example.com/service")
	assert.Contains(t, info.DNSNames, "test.example.com")
	assert.Contains(t, info.EmailAddresses, "test@example.com")

	// Verify subject info
	assert.NotNil(t, info.Subject)
	assert.Equal(t, "test-client", info.Subject.CommonName)
	assert.Contains(t, info.Subject.Organization, "Test Org")
	assert.Contains(t, info.Subject.OrganizationalUnit, "Test Unit")
	assert.Contains(t, info.Subject.Country, "US")
	assert.Contains(t, info.Subject.Province, "California")
	assert.Contains(t, info.Subject.Locality, "San Francisco")
}

func TestCertificateInfo_GetIdentity(t *testing.T) {
	t.Parallel()

	info := &CertificateInfo{
		SubjectDN:      "CN=test-client,O=Test Org",
		SPIFFEID:       "spiffe://example.org/workload/test",
		DNSNames:       []string{"test.example.com"},
		URIs:           []string{"https://example.com/service"},
		EmailAddresses: []string{"test@example.com"},
		Subject: &SubjectInfo{
			CommonName:         "test-client",
			Organization:       []string{"Test Org"},
			OrganizationalUnit: []string{"Test Unit"},
		},
	}

	tests := []struct {
		name     string
		config   *IdentityExtractionConfig
		expected string
	}{
		{
			name:     "nil config returns SubjectDN",
			config:   nil,
			expected: "CN=test-client,O=Test Org",
		},
		{
			name: "SPIFFE ID takes precedence",
			config: &IdentityExtractionConfig{
				SPIFFE:    true,
				SubjectDN: true,
			},
			expected: "spiffe://example.org/workload/test",
		},
		{
			name: "Subject field CN",
			config: &IdentityExtractionConfig{
				SubjectField: "CN",
			},
			expected: "test-client",
		},
		{
			name: "Subject field O",
			config: &IdentityExtractionConfig{
				SubjectField: "O",
			},
			expected: "Test Org",
		},
		{
			name: "Subject field OU",
			config: &IdentityExtractionConfig{
				SubjectField: "OU",
			},
			expected: "Test Unit",
		},
		{
			name: "DNS SAN",
			config: &IdentityExtractionConfig{
				SANDNS: true,
			},
			expected: "test.example.com",
		},
		{
			name: "URI SAN",
			config: &IdentityExtractionConfig{
				SANURI: true,
			},
			expected: "https://example.com/service",
		},
		{
			name: "Email SAN",
			config: &IdentityExtractionConfig{
				SANEmail: true,
			},
			expected: "test@example.com",
		},
		{
			name: "fallback to SubjectDN when no match",
			config: &IdentityExtractionConfig{
				SubjectField: "C", // Country is empty in Subject
			},
			expected: "CN=test-client,O=Test Org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := info.GetIdentity(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCertificateInfo_GetIdentity_EmptyFields(t *testing.T) {
	t.Parallel()

	info := &CertificateInfo{
		SubjectDN: "CN=test",
		Subject: &SubjectInfo{
			CommonName: "test",
			// All other fields are empty
		},
	}

	tests := []struct {
		name     string
		config   *IdentityExtractionConfig
		expected string
	}{
		{
			name: "empty Organization",
			config: &IdentityExtractionConfig{
				SubjectField: "O",
			},
			expected: "CN=test",
		},
		{
			name: "empty OrganizationalUnit",
			config: &IdentityExtractionConfig{
				SubjectField: "OU",
			},
			expected: "CN=test",
		},
		{
			name: "empty DNS names",
			config: &IdentityExtractionConfig{
				SANDNS: true,
			},
			expected: "CN=test",
		},
		{
			name: "empty URIs",
			config: &IdentityExtractionConfig{
				SANURI: true,
			},
			expected: "CN=test",
		},
		{
			name: "empty emails",
			config: &IdentityExtractionConfig{
				SANEmail: true,
			},
			expected: "CN=test",
		},
		{
			name: "SPIFFE disabled or empty",
			config: &IdentityExtractionConfig{
				SPIFFE: true,
			},
			expected: "CN=test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := info.GetIdentity(tt.config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseSPIFFEID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		spiffeID    string
		wantDomain  string
		wantPath    string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid SPIFFE ID",
			spiffeID:   "spiffe://example.org/workload/test",
			wantDomain: "example.org",
			wantPath:   "/workload/test",
			wantErr:    false,
		},
		{
			name:       "valid SPIFFE ID with nested path",
			spiffeID:   "spiffe://cluster.local/ns/default/sa/myservice",
			wantDomain: "cluster.local",
			wantPath:   "/ns/default/sa/myservice",
			wantErr:    false,
		},
		{
			name:       "valid SPIFFE ID with no path",
			spiffeID:   "spiffe://example.org",
			wantDomain: "example.org",
			wantPath:   "",
			wantErr:    false,
		},
		{
			name:        "invalid - not spiffe scheme",
			spiffeID:    "https://example.org/workload",
			wantErr:     true,
			errContains: "must start with spiffe://",
		},
		{
			name:        "invalid - empty string",
			spiffeID:    "",
			wantErr:     true,
			errContains: "must start with spiffe://",
		},
		{
			name:       "just spiffe://",
			spiffeID:   "spiffe://",
			wantDomain: "",
			wantPath:   "",
			wantErr:    false, // URL parsing succeeds but domain is empty
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			info, err := ParseSPIFFEID(tt.spiffeID)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, info)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, info)
				assert.Equal(t, tt.wantDomain, info.TrustDomain)
				assert.Equal(t, tt.wantPath, info.Path)
			}
		})
	}
}

func TestExtractSPIFFEID(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)

	tests := []struct {
		name     string
		uris     []*url.URL
		expected string
	}{
		{
			name:     "no URIs",
			uris:     nil,
			expected: "",
		},
		{
			name: "SPIFFE ID present",
			uris: func() []*url.URL {
				u, _ := url.Parse("spiffe://example.org/workload")
				return []*url.URL{u}
			}(),
			expected: "spiffe://example.org/workload",
		},
		{
			name: "SPIFFE ID among other URIs",
			uris: func() []*url.URL {
				u1, _ := url.Parse("https://example.com")
				u2, _ := url.Parse("spiffe://example.org/workload")
				u3, _ := url.Parse("http://other.com")
				return []*url.URL{u1, u2, u3}
			}(),
			expected: "spiffe://example.org/workload",
		},
		{
			name: "no SPIFFE ID",
			uris: func() []*url.URL {
				u, _ := url.Parse("https://example.com")
				return []*url.URL{u}
			}(),
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cert, _ := generateTestCert(t, caCert, caKey, func(c *x509.Certificate) {
				c.URIs = tt.uris
			})

			result := extractSPIFFEID(cert)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCalculateFingerprint(t *testing.T) {
	t.Parallel()

	caCert, caKey := generateTestCA(t)
	cert, _ := generateTestCert(t, caCert, caKey)

	fingerprint := calculateFingerprint(cert)

	// Fingerprint should be a hex-encoded SHA-256 hash (64 characters)
	assert.Len(t, fingerprint, 64)

	// Same certificate should produce same fingerprint
	fingerprint2 := calculateFingerprint(cert)
	assert.Equal(t, fingerprint, fingerprint2)

	// Different certificate should produce different fingerprint
	cert2, _ := generateTestCert(t, caCert, caKey)
	fingerprint3 := calculateFingerprint(cert2)
	assert.NotEqual(t, fingerprint, fingerprint3)
}

func TestValidatorWithIntermediateCerts(t *testing.T) {
	t.Parallel()

	// Generate root CA
	rootCert, rootKey := generateTestCA(t)
	rootPool := newTestCAPool(rootCert)

	// Generate intermediate CA
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			CommonName:   "Intermediate CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	require.NoError(t, err)

	intermediateCert, err := x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	// Generate client certificate signed by intermediate
	clientCert, _ := generateTestCert(t, intermediateCert, intermediateKey)

	config := &Config{
		Enabled: true,
	}

	v, err := NewValidator(config, WithCAPool(rootPool))
	require.NoError(t, err)

	// Validate with intermediate in chain
	info, err := v.Validate(context.Background(), clientCert, []*x509.Certificate{intermediateCert})
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// Validate without intermediate should fail
	info, err = v.Validate(context.Background(), clientCert, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCertificateUntrusted)
	assert.Nil(t, info)
}

func TestValidatorOptions(t *testing.T) {
	t.Parallel()

	caCert, _ := generateTestCA(t)
	caPool := newTestCAPool(caCert)

	t.Run("WithValidatorLogger", func(t *testing.T) {
		t.Parallel()

		logger := observability.NopLogger()
		config := &Config{Enabled: true}

		v, err := NewValidator(config, WithCAPool(caPool), WithValidatorLogger(logger))
		require.NoError(t, err)
		assert.NotNil(t, v)
	})

	t.Run("WithValidatorMetrics", func(t *testing.T) {
		t.Parallel()

		metrics := NewMetrics("test")
		config := &Config{Enabled: true}

		v, err := NewValidator(config, WithCAPool(caPool), WithValidatorMetrics(metrics))
		require.NoError(t, err)
		assert.NotNil(t, v)
	})

	t.Run("WithCAPool", func(t *testing.T) {
		t.Parallel()

		config := &Config{Enabled: true}

		v, err := NewValidator(config, WithCAPool(caPool))
		require.NoError(t, err)
		assert.NotNil(t, v)
	})
}

func TestCreateCAPool(t *testing.T) {
	t.Parallel()

	t.Run("empty config", func(t *testing.T) {
		t.Parallel()

		config := &Config{}
		pool, err := createCAPool(config)
		assert.NoError(t, err)
		assert.NotNil(t, pool)
	})

	t.Run("invalid CA cert PEM", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			CACert: "not a valid PEM",
		}
		pool, err := createCAPool(config)
		assert.Error(t, err)
		assert.Nil(t, pool)
	})

	t.Run("CA file not implemented", func(t *testing.T) {
		t.Parallel()

		config := &Config{
			CAFile: "/path/to/ca.crt",
		}
		pool, err := createCAPool(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
		assert.Nil(t, pool)
	})
}

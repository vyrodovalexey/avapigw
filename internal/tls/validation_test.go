package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertificate creates a test certificate with the given options.
func generateTestCertificate(t *testing.T, opts ...func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	for _, opt := range opts {
		opt(template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

func TestExtractClientIdentity(t *testing.T) {
	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "client.example.com"
		c.Subject.Organization = []string{"Test Org"}
		c.Subject.OrganizationalUnit = []string{"Test Unit"}
		c.DNSNames = []string{"client.example.com", "alt.example.com"}
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
		c.EmailAddresses = []string{"test@example.com"}
	})

	identity := ExtractClientIdentity(cert)

	assert.NotNil(t, identity)
	assert.Equal(t, "client.example.com", identity.CommonName)
	assert.Equal(t, []string{"Test Org"}, identity.Organization)
	assert.Equal(t, []string{"Test Unit"}, identity.OrganizationalUnit)
	assert.Contains(t, identity.DNSNames, "client.example.com")
	assert.Contains(t, identity.DNSNames, "alt.example.com")
	assert.Len(t, identity.IPAddresses, 1)
	assert.Contains(t, identity.EmailAddresses, "test@example.com")
}

func TestExtractClientIdentity_Nil(t *testing.T) {
	identity := ExtractClientIdentity(nil)
	assert.Nil(t, identity)
}

func TestValidator_ValidateClientCertificate(t *testing.T) {
	tests := []struct {
		name    string
		config  *ClientValidationConfig
		cert    func(t *testing.T) *x509.Certificate
		wantErr bool
		errMsg  string
	}{
		{
			name:   "nil certificate",
			config: &ClientValidationConfig{},
			cert: func(_ *testing.T) *x509.Certificate {
				return nil
			},
			wantErr: true,
			errMsg:  "certificate is nil",
		},
		{
			name:   "valid certificate",
			config: &ClientValidationConfig{},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t)
			},
			wantErr: false,
		},
		{
			name:   "expired certificate",
			config: &ClientValidationConfig{},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.NotAfter = time.Now().Add(-1 * time.Hour)
				})
			},
			wantErr: true,
			errMsg:  "expired",
		},
		{
			name:   "not yet valid certificate",
			config: &ClientValidationConfig{},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.NotBefore = time.Now().Add(1 * time.Hour)
				})
			},
			wantErr: true,
			errMsg:  "not yet valid",
		},
		{
			name: "allowed CN",
			config: &ClientValidationConfig{
				AllowedCNs: []string{"test.example.com"},
			},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t)
			},
			wantErr: false,
		},
		{
			name: "disallowed CN",
			config: &ClientValidationConfig{
				AllowedCNs: []string{"other.example.com"},
			},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t)
			},
			wantErr: true,
			errMsg:  "not in allowed list",
		},
		{
			name: "wildcard CN match",
			config: &ClientValidationConfig{
				AllowedCNs: []string{"*.example.com"},
			},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t)
			},
			wantErr: false,
		},
		{
			name: "allowed SAN",
			config: &ClientValidationConfig{
				AllowedSANs: []string{"alt.example.com"},
			},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.DNSNames = []string{"alt.example.com"}
				})
			},
			wantErr: false,
		},
		{
			name: "disallowed SAN",
			config: &ClientValidationConfig{
				AllowedSANs: []string{"other.example.com"},
			},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.DNSNames = []string{"alt.example.com"}
				})
			},
			wantErr: true,
			errMsg:  "no Subject Alternative Name matches",
		},
		{
			name: "no SANs when required",
			config: &ClientValidationConfig{
				AllowedSANs: []string{"any.example.com"},
			},
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.DNSNames = nil
					c.IPAddresses = nil
					c.EmailAddresses = nil
				})
			},
			wantErr: true,
			errMsg:  "no Subject Alternative Names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewValidator(tt.config)
			cert := tt.cert(t)

			err := validator.ValidateClientCertificate(cert)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		value   string
		pattern string
		match   bool
	}{
		{"test.example.com", "test.example.com", true},
		{"test.example.com", "TEST.EXAMPLE.COM", true}, // case insensitive
		{"test.example.com", "other.example.com", false},
		{"test.example.com", "*", true},
		{"test.example.com", "*.example.com", true},
		{"sub.test.example.com", "*.example.com", true},
		{"example.com", "*.example.com", true}, // matches the base domain
		{"test.other.com", "*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.value+"_"+tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.match, matchPattern(tt.value, tt.pattern))
		})
	}
}

func TestCheckCertificateExpiration(t *testing.T) {
	tests := []struct {
		name         string
		cert         func(t *testing.T) *x509.Certificate
		threshold    time.Duration
		expired      bool
		expiringSoon bool
	}{
		{
			name: "valid certificate",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.NotAfter = time.Now().Add(30 * 24 * time.Hour)
				})
			},
			threshold:    7 * 24 * time.Hour,
			expired:      false,
			expiringSoon: false,
		},
		{
			name: "expired certificate",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.NotAfter = time.Now().Add(-1 * time.Hour)
				})
			},
			threshold:    7 * 24 * time.Hour,
			expired:      true,
			expiringSoon: false,
		},
		{
			name: "expiring soon",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.NotAfter = time.Now().Add(3 * 24 * time.Hour)
				})
			},
			threshold:    7 * 24 * time.Hour,
			expired:      false,
			expiringSoon: true,
		},
		{
			name: "nil certificate",
			cert: func(_ *testing.T) *x509.Certificate {
				return nil
			},
			threshold:    7 * 24 * time.Hour,
			expired:      true,
			expiringSoon: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.cert(t)
			expired, expiringSoon, _ := CheckCertificateExpiration(cert, tt.threshold)
			assert.Equal(t, tt.expired, expired)
			assert.Equal(t, tt.expiringSoon, expiringSoon)
		})
	}
}

func TestCheckCertificateExpirationStatus(t *testing.T) {
	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(3 * 24 * time.Hour)
	})

	status := CheckCertificateExpirationStatus(cert, 7*24*time.Hour)

	assert.False(t, status.Expired)
	assert.True(t, status.ExpiringSoon)
	assert.Greater(t, status.TimeUntilExpiry, time.Duration(0))
}

func TestIsSelfSigned(t *testing.T) {
	// Self-signed certificate - need to create one where issuer == subject
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Self Signed CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the certificate (issuer == subject)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	selfSigned, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	assert.True(t, IsSelfSigned(selfSigned))

	// Nil certificate
	assert.False(t, IsSelfSigned(nil))
}

func TestValidateCertificateForHost(t *testing.T) {
	tests := []struct {
		name    string
		cert    func(t *testing.T) *x509.Certificate
		host    string
		wantErr bool
	}{
		{
			name: "matching DNS name",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.DNSNames = []string{"test.example.com"}
				})
			},
			host:    "test.example.com",
			wantErr: false,
		},
		{
			name: "matching CN",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.Subject.CommonName = "test.example.com"
				})
			},
			host:    "test.example.com",
			wantErr: false,
		},
		{
			name: "matching IP",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
				})
			},
			host:    "192.168.1.1",
			wantErr: false,
		},
		{
			name: "wildcard match",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.DNSNames = []string{"*.example.com"}
				})
			},
			host:    "test.example.com",
			wantErr: false,
		},
		{
			name: "no match",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t, func(c *x509.Certificate) {
					c.Subject.CommonName = "other.example.com"
					c.DNSNames = []string{"other.example.com"}
				})
			},
			host:    "test.example.com",
			wantErr: true,
		},
		{
			name: "empty host",
			cert: func(t *testing.T) *x509.Certificate {
				return generateTestCertificate(t)
			},
			host:    "",
			wantErr: false,
		},
		{
			name: "nil certificate",
			cert: func(_ *testing.T) *x509.Certificate {
				return nil
			},
			host:    "test.example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := tt.cert(t)
			err := ValidateCertificateForHost(cert, tt.host)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMatchHostname(t *testing.T) {
	tests := []struct {
		host    string
		pattern string
		match   bool
	}{
		{"test.example.com", "test.example.com", true},
		{"test.example.com", "TEST.EXAMPLE.COM", true},
		{"test.example.com", "other.example.com", false},
		{"test.example.com", "*.example.com", true},
		{"sub.test.example.com", "*.example.com", false}, // wildcard only matches one level
		{"example.com", "*.example.com", false},          // no subdomain
		{"test.example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.host+"_"+tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.match, matchHostname(tt.host, tt.pattern))
		})
	}
}

func TestAnalyzeCertificateChain(t *testing.T) {
	// Create a proper self-signed root
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Root CA",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Create leaf and intermediate (not self-signed)
	leaf := generateTestCertificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "leaf.example.com"
		c.IsCA = false
	})

	intermediate := generateTestCertificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Intermediate CA"
		c.IsCA = true
	})

	chain := []*x509.Certificate{leaf, intermediate, root}
	info := AnalyzeCertificateChain(chain)

	assert.NotNil(t, info)
	assert.Equal(t, 3, info.ChainLength)
	assert.NotNil(t, info.Leaf)
	assert.Contains(t, info.Leaf.Subject, "leaf.example.com")
	// The intermediate is not self-signed, so it goes to intermediates
	// The root is self-signed, so it goes to Root
	assert.NotNil(t, info.Root)
	assert.True(t, info.IsComplete)
}

func TestAnalyzeCertificateChain_Empty(t *testing.T) {
	info := AnalyzeCertificateChain(nil)
	assert.Nil(t, info)

	info = AnalyzeCertificateChain([]*x509.Certificate{})
	assert.Nil(t, info)
}

func TestFilterExpiredCertificates(t *testing.T) {
	valid := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(24 * time.Hour)
	})

	expired := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(-1 * time.Hour)
	})

	notYetValid := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(1 * time.Hour)
	})

	certs := []*x509.Certificate{valid, expired, notYetValid, nil}
	filtered := FilterExpiredCertificates(certs)

	assert.Len(t, filtered, 1)
	assert.Equal(t, valid, filtered[0])
}

func TestSortCertificatesByExpiry(t *testing.T) {
	cert1 := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(30 * 24 * time.Hour)
	})

	cert2 := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(7 * 24 * time.Hour)
	})

	cert3 := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(14 * 24 * time.Hour)
	})

	certs := []*x509.Certificate{cert1, cert2, cert3}
	SortCertificatesByExpiry(certs)

	// Should be sorted by expiry (earliest first)
	assert.Equal(t, cert2, certs[0])
	assert.Equal(t, cert3, certs[1])
	assert.Equal(t, cert1, certs[2])
}

func TestCollectSANs(t *testing.T) {
	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"dns1.example.com", "dns2.example.com"}
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
		c.EmailAddresses = []string{"test@example.com"}
	})

	sans := collectSANs(cert)

	assert.Len(t, sans, 4)
	assert.Contains(t, sans, "dns1.example.com")
	assert.Contains(t, sans, "dns2.example.com")
	assert.Contains(t, sans, "192.168.1.1")
	assert.Contains(t, sans, "test@example.com")
}

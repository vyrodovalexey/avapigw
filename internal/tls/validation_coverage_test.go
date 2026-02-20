package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetCertificateFingerprint tests GetCertificateFingerprint function.
func TestGetCertificateFingerprint(t *testing.T) {
	t.Parallel()

	// Test with nil certificate
	fingerprint := GetCertificateFingerprint(nil)
	assert.Empty(t, fingerprint)

	// Test with valid certificate
	cert := generateTestCertificate(t)
	fingerprint = GetCertificateFingerprint(cert)
	// SHA-256 fingerprint should be a colon-separated hex string
	assert.NotEmpty(t, fingerprint)
	assert.Contains(t, fingerprint, ":")
}

// TestSha256Sum tests sha256Sum function.
func TestSha256Sum(t *testing.T) {
	t.Parallel()

	// Test with some data
	data := []byte("test data")
	result := sha256Sum(data)

	// SHA-256 hash should be 32 bytes
	assert.NotNil(t, result)
	assert.Len(t, result, 32)
}

// TestFormatFingerprint tests formatFingerprint function.
func TestFormatFingerprint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hash     []byte
		expected string
	}{
		{
			name:     "empty hash",
			hash:     []byte{},
			expected: "",
		},
		{
			name:     "nil hash",
			hash:     nil,
			expected: "",
		},
		{
			name:     "single byte",
			hash:     []byte{0xAB},
			expected: "AB",
		},
		{
			name:     "multiple bytes",
			hash:     []byte{0xAB, 0xCD, 0xEF},
			expected: "AB:CD:EF",
		},
		{
			name:     "sha256 hash",
			hash:     sha256.New().Sum(nil)[:4], // First 4 bytes
			expected: "E3:B0:C4:42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := formatFingerprint(tt.hash)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSelfSigned_NotSelfSigned tests IsSelfSigned with a non-self-signed certificate.
func TestIsSelfSigned_NotSelfSigned(t *testing.T) {
	t.Parallel()

	// Create a certificate where issuer != subject
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Leaf Certificate",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "Different Issuer",
			Organization: []string{"Issuer Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// This certificate has different issuer and subject, so it's not self-signed
	// However, since we self-signed it in CreateCertificate, the signature will verify
	// The function checks both issuer==subject AND signature verification
	result := IsSelfSigned(cert)
	// The issuer and subject are different, so it should return false
	assert.False(t, result)
}

// TestExtractClientIdentity_WithURIs tests ExtractClientIdentity with URIs.
func TestExtractClientIdentity_WithURIs(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	uri1, _ := url.Parse("spiffe://example.com/service")
	uri2, _ := url.Parse("https://example.com/client")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri1, uri2},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	identity := ExtractClientIdentity(cert)

	require.NotNil(t, identity)
	assert.Len(t, identity.URIs, 2)
	assert.Contains(t, identity.URIs, "spiffe://example.com/service")
	assert.Contains(t, identity.URIs, "https://example.com/client")
}

// TestValidator_ValidateCommonName_EmptyCN tests validateCommonName with empty CN.
func TestValidator_ValidateCommonName_EmptyCN(t *testing.T) {
	t.Parallel()

	config := &ClientValidationConfig{
		AllowedCNs: []string{"allowed.example.com"},
	}

	validator := NewValidator(config)

	// Create certificate with empty CN
	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = ""
	})

	err := validator.validateCommonName(cert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Common Name")
}

// TestValidator_ValidateSANs_IPMatch tests validateSANs with IP address match.
func TestValidator_ValidateSANs_IPMatch(t *testing.T) {
	t.Parallel()

	config := &ClientValidationConfig{
		AllowedSANs: []string{"192.168.1.1"},
	}

	validator := NewValidator(config)

	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
	})

	err := validator.validateSANs(cert)
	require.NoError(t, err)
}

// TestValidator_ValidateSANs_EmailMatch tests validateSANs with email address match.
func TestValidator_ValidateSANs_EmailMatch(t *testing.T) {
	t.Parallel()

	config := &ClientValidationConfig{
		AllowedSANs: []string{"test@example.com"},
	}

	validator := NewValidator(config)

	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.EmailAddresses = []string{"test@example.com"}
	})

	err := validator.validateSANs(cert)
	require.NoError(t, err)
}

// TestValidator_ValidateSANs_URIMatch tests validateSANs with URI match.
func TestValidator_ValidateSANs_URIMatch(t *testing.T) {
	t.Parallel()

	config := &ClientValidationConfig{
		AllowedSANs: []string{"spiffe://example.com/service"},
	}

	validator := NewValidator(config)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	uri, _ := url.Parse("spiffe://example.com/service")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	err = validator.validateSANs(cert)
	require.NoError(t, err)
}

// TestValidator_ValidateSANs_WildcardMatch tests validateSANs with wildcard match.
func TestValidator_ValidateSANs_WildcardMatch(t *testing.T) {
	t.Parallel()

	config := &ClientValidationConfig{
		AllowedSANs: []string{"*.example.com"},
	}

	validator := NewValidator(config)

	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.DNSNames = []string{"test.example.com"}
	})

	err := validator.validateSANs(cert)
	require.NoError(t, err)
}

// TestValidateCertificateChain_WithOptions tests ValidateCertificateChain with custom options.
func TestValidateCertificateChain_WithOptions(t *testing.T) {
	t.Parallel()

	// Create a self-signed root CA
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Root CA",
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

	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Create a leaf certificate signed by the root
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com"},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Create root pool
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	// Test with custom options
	opts := x509.VerifyOptions{
		DNSName:   "test.example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	err = ValidateCertificateChain([]*x509.Certificate{leafCert}, roots, opts)
	require.NoError(t, err)
}

// TestValidateCertificateChain_InvalidChain tests ValidateCertificateChain with invalid chain.
func TestValidateCertificateChain_InvalidChain(t *testing.T) {
	t.Parallel()

	// Create a self-signed certificate (not a CA)
	cert := generateTestCertificate(t)

	// Create an empty root pool (no trusted roots)
	roots := x509.NewCertPool()

	err := ValidateCertificateChain([]*x509.Certificate{cert}, roots)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

// TestSortCertificatesByExpiry_SameExpiry tests SortCertificatesByExpiry with same expiry.
func TestSortCertificatesByExpiry_SameExpiry(t *testing.T) {
	t.Parallel()

	expiry := time.Now().Add(24 * time.Hour)

	cert1 := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = expiry
		c.Subject.CommonName = "cert1"
	})

	cert2 := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = expiry
		c.Subject.CommonName = "cert2"
	})

	certs := []*x509.Certificate{cert1, cert2}
	SortCertificatesByExpiry(certs)

	// Order should be stable when expiry is the same
	assert.Len(t, certs, 2)
}

// TestAnalyzeCertificateChain_NoRoot tests AnalyzeCertificateChain without a root.
func TestAnalyzeCertificateChain_NoRoot(t *testing.T) {
	t.Parallel()

	// Create certificates that are not self-signed
	leaf := generateTestCertificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "leaf.example.com"
		c.IsCA = false
	})

	intermediate := generateTestCertificate(t, func(c *x509.Certificate) {
		c.Subject.CommonName = "Intermediate CA"
		c.IsCA = true
	})

	chain := []*x509.Certificate{leaf, intermediate}
	info := AnalyzeCertificateChain(chain)

	require.NotNil(t, info)
	assert.Equal(t, 2, info.ChainLength)
	assert.NotNil(t, info.Leaf)
	assert.Nil(t, info.Root) // No self-signed root
	assert.False(t, info.IsComplete)
}

// TestMatchHostname_EdgeCases tests matchHostname with edge cases.
func TestMatchHostname_EdgeCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		host    string
		pattern string
		match   bool
	}{
		// Empty cases
		{"", "", false},
		{"host", "", false},
		{"", "pattern", false},

		// Exact match
		{"example.com", "example.com", true},
		{"EXAMPLE.COM", "example.com", true},

		// Wildcard cases
		{"sub.example.com", "*.example.com", true},
		{"deep.sub.example.com", "*.example.com", false}, // Only one level
		{"example.com", "*.example.com", false},          // No subdomain

		// No match
		{"other.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host+"_"+tt.pattern, func(t *testing.T) {
			t.Parallel()
			result := matchHostname(tt.host, tt.pattern)
			assert.Equal(t, tt.match, result)
		})
	}
}

// TestValidateCertificateForHost_IPMismatch tests ValidateCertificateForHost with IP mismatch.
func TestValidateCertificateForHost_IPMismatch(t *testing.T) {
	t.Parallel()

	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.IPAddresses = []net.IP{net.ParseIP("192.168.1.1")}
		c.Subject.CommonName = "other.example.com"
		c.DNSNames = nil
	})

	err := ValidateCertificateForHost(cert, "192.168.1.2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid for host")
}

// TestCollectSANs_AllTypes tests collectSANs with all SAN types.
func TestCollectSANs_AllTypes(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	uri, _ := url.Parse("spiffe://example.com/service")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"dns1.example.com", "dns2.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
		EmailAddresses:        []string{"test@example.com"},
		URIs:                  []*url.URL{uri},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	sans := collectSANs(cert)

	assert.Len(t, sans, 6) // 2 DNS + 2 IP + 1 Email + 1 URI
	assert.Contains(t, sans, "dns1.example.com")
	assert.Contains(t, sans, "dns2.example.com")
	assert.Contains(t, sans, "192.168.1.1")
	assert.Contains(t, sans, "10.0.0.1")
	assert.Contains(t, sans, "test@example.com")
	assert.Contains(t, sans, "spiffe://example.com/service")
}

// TestCheckCertificateExpirationStatus_ValidCertificate tests CheckCertificateExpirationStatus with valid certificate.
func TestCheckCertificateExpirationStatus_ValidCertificate(t *testing.T) {
	t.Parallel()

	cert := generateTestCertificate(t, func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(30 * 24 * time.Hour) // 30 days
	})

	status := CheckCertificateExpirationStatus(cert, 7*24*time.Hour)

	assert.False(t, status.Expired)
	assert.False(t, status.ExpiringSoon)
	assert.Greater(t, status.TimeUntilExpiry, time.Duration(0))
}

// TestMatchPattern_AllWildcard tests matchPattern with "*" wildcard.
func TestMatchPattern_AllWildcard(t *testing.T) {
	t.Parallel()

	assert.True(t, matchPattern("anything", "*"))
	assert.True(t, matchPattern("", "*"))
	assert.True(t, matchPattern("test.example.com", "*"))
}

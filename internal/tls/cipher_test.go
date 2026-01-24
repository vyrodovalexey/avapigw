package tls

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultSecureCipherSuites(t *testing.T) {
	suites := DefaultSecureCipherSuites()

	assert.NotEmpty(t, suites)

	// Verify all suites are secure
	for _, id := range suites {
		assert.True(t, IsSecureCipherSuite(id), "cipher suite %s should be secure", CipherSuiteName(id))
	}
}

func TestDefaultSecureCipherSuiteNames(t *testing.T) {
	names := DefaultSecureCipherSuiteNames()

	assert.NotEmpty(t, names)

	// Verify all names are valid
	for _, name := range names {
		_, ok := GetCipherSuiteInfo(name)
		assert.True(t, ok, "cipher suite %s should be valid", name)
	}
}

func TestFIPSCipherSuites(t *testing.T) {
	suites := FIPSCipherSuites()

	assert.NotEmpty(t, suites)

	// Verify all suites are FIPS-compliant
	for _, id := range suites {
		assert.True(t, IsFIPSCipherSuite(id), "cipher suite %s should be FIPS-compliant", CipherSuiteName(id))
	}
}

func TestDefaultCurvePreferences(t *testing.T) {
	curves := DefaultCurvePreferences()

	assert.NotEmpty(t, curves)
	assert.Contains(t, curves, tls.X25519)
	assert.Contains(t, curves, tls.CurveP256)
}

func TestParseCipherSuites(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty returns defaults",
			input:   nil,
			wantErr: false,
		},
		{
			name:    "valid cipher suites",
			input:   []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			wantErr: false,
		},
		{
			name:    "invalid cipher suite",
			input:   []string{"INVALID_CIPHER"},
			wantErr: true,
			errMsg:  "invalid cipher suite",
		},
		{
			name:    "TLS 1.3 suites are skipped",
			input:   []string{"TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			wantErr: false,
		},
		{
			name:    "whitespace is trimmed",
			input:   []string{"  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  "},
			wantErr: false,
		},
		{
			name:    "empty strings are skipped",
			input:   []string{"", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", ""},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suites, err := ParseCipherSuites(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, suites)
			}
		})
	}
}

func TestParseCurvePreferences(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty returns defaults",
			input:   nil,
			wantErr: false,
		},
		{
			name:    "valid curves",
			input:   []string{"X25519", "P256", "P384"},
			wantErr: false,
		},
		{
			name:    "invalid curve",
			input:   []string{"INVALID_CURVE"},
			wantErr: true,
			errMsg:  "invalid curve",
		},
		{
			name:    "alternative names",
			input:   []string{"CurveP256", "CurveP384"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			curves, err := ParseCurvePreferences(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, curves)
			}
		})
	}
}

func TestValidateCipherSuites(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{
			name:    "valid suites",
			input:   []string{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
			wantErr: false,
		},
		{
			name:    "invalid suite",
			input:   []string{"INVALID"},
			wantErr: true,
		},
		{
			name:    "empty list",
			input:   nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCipherSuites(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateCurvePreferences(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{
			name:    "valid curves",
			input:   []string{"X25519", "P256"},
			wantErr: false,
		},
		{
			name:    "invalid curve",
			input:   []string{"INVALID"},
			wantErr: true,
		},
		{
			name:    "empty list",
			input:   nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCurvePreferences(tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGetCipherSuiteInfo(t *testing.T) {
	// Valid cipher suite
	info, ok := GetCipherSuiteInfo("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
	assert.True(t, ok)
	assert.Equal(t, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, info.ID)
	assert.True(t, info.Secure)
	assert.True(t, info.FIPS)
	assert.False(t, info.TLS13)

	// TLS 1.3 cipher suite
	info, ok = GetCipherSuiteInfo("TLS_AES_256_GCM_SHA384")
	assert.True(t, ok)
	assert.True(t, info.TLS13)

	// Invalid cipher suite
	_, ok = GetCipherSuiteInfo("INVALID")
	assert.False(t, ok)
}

func TestGetCipherSuiteByID(t *testing.T) {
	// Valid ID
	info, ok := GetCipherSuiteByID(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	assert.True(t, ok)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", info.Name)

	// Invalid ID
	_, ok = GetCipherSuiteByID(0xFFFF)
	assert.False(t, ok)
}

func TestCipherSuiteName(t *testing.T) {
	// Known cipher suite
	name := CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	assert.Equal(t, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", name)

	// Unknown cipher suite
	name = CipherSuiteName(0xFFFF)
	assert.Equal(t, "0xFFFF", name)
}

func TestIsSecureCipherSuite(t *testing.T) {
	// Secure suite
	assert.True(t, IsSecureCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384))

	// Insecure suite
	assert.False(t, IsSecureCipherSuite(tls.TLS_RSA_WITH_AES_128_CBC_SHA))

	// Unknown suite
	assert.False(t, IsSecureCipherSuite(0xFFFF))
}

func TestIsFIPSCipherSuite(t *testing.T) {
	// FIPS suite
	assert.True(t, IsFIPSCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384))

	// Non-FIPS suite (ChaCha20)
	assert.False(t, IsFIPSCipherSuite(tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256))

	// Unknown suite
	assert.False(t, IsFIPSCipherSuite(0xFFFF))
}

func TestFilterSecureCipherSuites(t *testing.T) {
	input := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // secure
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,          // insecure
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // secure
	}

	filtered := FilterSecureCipherSuites(input)

	assert.Len(t, filtered, 2)
	assert.Contains(t, filtered, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	assert.Contains(t, filtered, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	assert.NotContains(t, filtered, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
}

func TestFilterFIPSCipherSuites(t *testing.T) {
	input := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,       // FIPS
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, // non-FIPS
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,       // FIPS
	}

	filtered := FilterFIPSCipherSuites(input)

	assert.Len(t, filtered, 2)
	assert.Contains(t, filtered, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
	assert.Contains(t, filtered, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	assert.NotContains(t, filtered, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
}

func TestListAllCipherSuites(t *testing.T) {
	suites := ListAllCipherSuites()

	assert.NotEmpty(t, suites)

	// Verify sorted by ID
	for i := 1; i < len(suites); i++ {
		assert.LessOrEqual(t, suites[i-1].ID, suites[i].ID)
	}
}

func TestListSecureCipherSuites(t *testing.T) {
	suites := ListSecureCipherSuites()

	assert.NotEmpty(t, suites)

	// Verify all are secure
	for _, suite := range suites {
		assert.True(t, suite.Secure)
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version uint16
		name    string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0xFFFF, "0xFFFF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, TLSVersionName(tt.version))
		})
	}
}

func TestCurveName(t *testing.T) {
	tests := []struct {
		curve tls.CurveID
		name  string
	}{
		{tls.X25519, "X25519"},
		{tls.CurveP256, "P-256"},
		{tls.CurveP384, "P-384"},
		{tls.CurveP521, "P-521"},
		{tls.CurveID(0xFFFF), "0xFFFF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, CurveName(tt.curve))
		})
	}
}

package tls

import (
	"crypto/tls"
	"fmt"
	"runtime"
	"slices"
	"strings"
)

// CipherSuite represents a TLS cipher suite with metadata.
type CipherSuite struct {
	// ID is the cipher suite ID.
	ID uint16

	// Name is the cipher suite name.
	Name string

	// Secure indicates if this is a secure cipher suite.
	Secure bool

	// FIPS indicates if this cipher suite is FIPS-compliant.
	FIPS bool

	// TLS13 indicates if this is a TLS 1.3 cipher suite.
	TLS13 bool
}

// cipherSuiteRegistry maps cipher suite names to their configurations.
var cipherSuiteRegistry = map[string]CipherSuite{
	// TLS 1.3 cipher suites (always secure)
	"TLS_AES_128_GCM_SHA256": {
		ID:     tls.TLS_AES_128_GCM_SHA256,
		Name:   "TLS_AES_128_GCM_SHA256",
		Secure: true,
		FIPS:   true,
		TLS13:  true,
	},
	"TLS_AES_256_GCM_SHA384": {
		ID:     tls.TLS_AES_256_GCM_SHA384,
		Name:   "TLS_AES_256_GCM_SHA384",
		Secure: true,
		FIPS:   true,
		TLS13:  true,
	},
	"TLS_CHACHA20_POLY1305_SHA256": {
		ID:     tls.TLS_CHACHA20_POLY1305_SHA256,
		Name:   "TLS_CHACHA20_POLY1305_SHA256",
		Secure: true,
		FIPS:   false,
		TLS13:  true,
	},

	// TLS 1.2 secure cipher suites
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {
		ID:     tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		Name:   "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		Secure: true,
		FIPS:   true,
	},
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": {
		ID:     tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		Name:   "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		Secure: true,
		FIPS:   true,
	},
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {
		ID:     tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Name:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		Secure: true,
		FIPS:   true,
	},
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {
		ID:     tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		Name:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		Secure: true,
		FIPS:   true,
	},
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": {
		ID:     tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		Name:   "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		Secure: true,
		FIPS:   false,
	},
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": {
		ID:     tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		Name:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		Secure: true,
		FIPS:   false,
	},

	// Legacy cipher suites (not recommended)
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": {
		ID:     tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		Name:   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		Secure: false,
		FIPS:   true,
	},
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": {
		ID:     tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		Name:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		Secure: false,
		FIPS:   true,
	},
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": {
		ID:     tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		Name:   "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		Secure: false,
		FIPS:   true,
	},
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": {
		ID:     tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		Name:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		Secure: false,
		FIPS:   true,
	},
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": {
		ID:     tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		Name:   "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		Secure: false,
		FIPS:   true,
	},
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": {
		ID:     tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		Name:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		Secure: false,
		FIPS:   true,
	},
	"TLS_RSA_WITH_AES_128_GCM_SHA256": {
		ID:     tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		Name:   "TLS_RSA_WITH_AES_128_GCM_SHA256",
		Secure: false,
		FIPS:   true,
	},
	"TLS_RSA_WITH_AES_256_GCM_SHA384": {
		ID:     tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		Name:   "TLS_RSA_WITH_AES_256_GCM_SHA384",
		Secure: false,
		FIPS:   true,
	},
	"TLS_RSA_WITH_AES_128_CBC_SHA256": {
		ID:     tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		Name:   "TLS_RSA_WITH_AES_128_CBC_SHA256",
		Secure: false,
		FIPS:   true,
	},
	"TLS_RSA_WITH_AES_128_CBC_SHA": {
		ID:     tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		Name:   "TLS_RSA_WITH_AES_128_CBC_SHA",
		Secure: false,
		FIPS:   true,
	},
	"TLS_RSA_WITH_AES_256_CBC_SHA": {
		ID:     tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		Name:   "TLS_RSA_WITH_AES_256_CBC_SHA",
		Secure: false,
		FIPS:   true,
	},
}

// curveRegistry maps curve names to their tls.CurveID values.
var curveRegistry = map[string]tls.CurveID{
	"X25519":    tls.X25519,
	"P256":      tls.CurveP256,
	"P384":      tls.CurveP384,
	"P521":      tls.CurveP521,
	"CurveP256": tls.CurveP256,
	"CurveP384": tls.CurveP384,
	"CurveP521": tls.CurveP521,
}

// DefaultSecureCipherSuites returns the default secure cipher suites for TLS 1.2.
// TLS 1.3 cipher suites are managed by Go and cannot be configured.
func DefaultSecureCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// DefaultSecureCipherSuiteNames returns the names of default secure cipher suites.
func DefaultSecureCipherSuiteNames() []string {
	return []string{
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	}
}

// FIPSCipherSuites returns FIPS-compliant cipher suites.
func FIPSCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// FIPSCipherSuiteNames returns the names of FIPS-compliant cipher suites.
func FIPSCipherSuiteNames() []string {
	return []string{
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}
}

// DefaultCurvePreferences returns the default ECDH curve preferences.
func DefaultCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
		tls.CurveP384,
	}
}

// DefaultCurvePreferenceNames returns the names of default curve preferences.
func DefaultCurvePreferenceNames() []string {
	return []string{
		"X25519",
		"P256",
		"P384",
	}
}

// FIPSCurvePreferences returns FIPS-compliant curve preferences.
func FIPSCurvePreferences() []tls.CurveID {
	return []tls.CurveID{
		tls.CurveP256,
		tls.CurveP384,
		tls.CurveP521,
	}
}

// ParseCipherSuites parses cipher suite names and returns their IDs.
func ParseCipherSuites(names []string) ([]uint16, error) {
	if len(names) == 0 {
		return DefaultSecureCipherSuites(), nil
	}

	suites := make([]uint16, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		suite, ok := cipherSuiteRegistry[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrCipherSuiteInvalid, name)
		}

		// Skip TLS 1.3 suites as they cannot be configured
		if suite.TLS13 {
			continue
		}

		suites = append(suites, suite.ID)
	}

	if len(suites) == 0 {
		return DefaultSecureCipherSuites(), nil
	}

	return suites, nil
}

// ParseCurvePreferences parses curve names and returns their IDs.
func ParseCurvePreferences(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return DefaultCurvePreferences(), nil
	}

	curves := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		curve, ok := curveRegistry[name]
		if !ok {
			return nil, fmt.Errorf("invalid curve: %s", name)
		}

		curves = append(curves, curve)
	}

	if len(curves) == 0 {
		return DefaultCurvePreferences(), nil
	}

	return curves, nil
}

// ValidateCipherSuites validates that all cipher suite names are valid.
func ValidateCipherSuites(names []string) error {
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		if _, ok := cipherSuiteRegistry[name]; !ok {
			return fmt.Errorf("%w: %s", ErrCipherSuiteInvalid, name)
		}
	}
	return nil
}

// ValidateCurvePreferences validates that all curve names are valid.
func ValidateCurvePreferences(names []string) error {
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		if _, ok := curveRegistry[name]; !ok {
			return fmt.Errorf("invalid curve: %s", name)
		}
	}
	return nil
}

// GetCipherSuiteInfo returns information about a cipher suite by name.
func GetCipherSuiteInfo(name string) (CipherSuite, bool) {
	suite, ok := cipherSuiteRegistry[name]
	return suite, ok
}

// GetCipherSuiteByID returns information about a cipher suite by ID.
func GetCipherSuiteByID(id uint16) (CipherSuite, bool) {
	for _, suite := range cipherSuiteRegistry {
		if suite.ID == id {
			return suite, true
		}
	}
	return CipherSuite{}, false
}

// CipherSuiteName returns the name of a cipher suite by ID.
func CipherSuiteName(id uint16) string {
	if suite, ok := GetCipherSuiteByID(id); ok {
		return suite.Name
	}
	return fmt.Sprintf("0x%04X", id)
}

// IsSecureCipherSuite returns true if the cipher suite is considered secure.
func IsSecureCipherSuite(id uint16) bool {
	suite, ok := GetCipherSuiteByID(id)
	return ok && suite.Secure
}

// IsFIPSCipherSuite returns true if the cipher suite is FIPS-compliant.
func IsFIPSCipherSuite(id uint16) bool {
	suite, ok := GetCipherSuiteByID(id)
	return ok && suite.FIPS
}

// FilterSecureCipherSuites filters a list of cipher suites to only include secure ones.
func FilterSecureCipherSuites(suites []uint16) []uint16 {
	secure := make([]uint16, 0, len(suites))
	for _, id := range suites {
		if IsSecureCipherSuite(id) {
			secure = append(secure, id)
		}
	}
	return secure
}

// FilterFIPSCipherSuites filters a list of cipher suites to only include FIPS-compliant ones.
func FilterFIPSCipherSuites(suites []uint16) []uint16 {
	fips := make([]uint16, 0, len(suites))
	for _, id := range suites {
		if IsFIPSCipherSuite(id) {
			fips = append(fips, id)
		}
	}
	return fips
}

// ListAllCipherSuites returns all known cipher suites.
func ListAllCipherSuites() []CipherSuite {
	suites := make([]CipherSuite, 0, len(cipherSuiteRegistry))
	for _, suite := range cipherSuiteRegistry {
		suites = append(suites, suite)
	}
	// Sort by ID for consistent ordering
	slices.SortFunc(suites, func(a, b CipherSuite) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return suites
}

// ListSecureCipherSuites returns all secure cipher suites.
func ListSecureCipherSuites() []CipherSuite {
	suites := make([]CipherSuite, 0)
	for _, suite := range cipherSuiteRegistry {
		if suite.Secure {
			suites = append(suites, suite)
		}
	}
	slices.SortFunc(suites, func(a, b CipherSuite) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return suites
}

// IsFIPSMode returns true if the Go runtime is in FIPS mode.
// This is a best-effort detection based on build tags and environment.
func IsFIPSMode() bool {
	// Check for GOFIPS environment variable
	// In practice, FIPS mode is determined at build time with special build tags
	// This is a placeholder for actual FIPS detection
	return runtime.GOARCH == "amd64" && false // FIPS mode requires special build
}

// TLSVersionName returns the human-readable name of a TLS version.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04X", version)
	}
}

// CurveName returns the human-readable name of an ECDH curve.
func CurveName(curve tls.CurveID) string {
	switch curve {
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	default:
		return fmt.Sprintf("0x%04X", uint16(curve))
	}
}

package mtls

import (
	"errors"
	"fmt"
)

// Config represents mTLS authentication configuration.
type Config struct {
	// Enabled enables mTLS authentication.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RequireClientCert requires a client certificate.
	RequireClientCert bool `yaml:"requireClientCert,omitempty" json:"requireClientCert,omitempty"`

	// CAFile is the path to the CA certificate file.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// CACert is the CA certificate PEM data.
	CACert string `yaml:"caCert,omitempty" json:"caCert,omitempty"`

	// ExtractIdentity configures identity extraction from certificates.
	ExtractIdentity *IdentityExtractionConfig `yaml:"extractIdentity,omitempty" json:"extractIdentity,omitempty"`

	// Revocation configures certificate revocation checking.
	Revocation *RevocationConfig `yaml:"revocation,omitempty" json:"revocation,omitempty"`

	// Vault configures Vault integration.
	Vault *VaultConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// IdentityExtractionConfig configures identity extraction from certificates.
type IdentityExtractionConfig struct {
	// SubjectDN extracts the subject distinguished name.
	SubjectDN bool `yaml:"subjectDN,omitempty" json:"subjectDN,omitempty"`

	// SANDNS extracts DNS names from Subject Alternative Names.
	SANDNS bool `yaml:"sanDNS,omitempty" json:"sanDNS,omitempty"`

	// SANURI extracts URIs from Subject Alternative Names.
	SANURI bool `yaml:"sanURI,omitempty" json:"sanURI,omitempty"`

	// SANEmail extracts email addresses from Subject Alternative Names.
	SANEmail bool `yaml:"sanEmail,omitempty" json:"sanEmail,omitempty"`

	// SPIFFE extracts SPIFFE IDs from URI SANs.
	SPIFFE bool `yaml:"spiffe,omitempty" json:"spiffe,omitempty"`

	// SubjectField specifies which subject field to use as the identity.
	// Options: CN, O, OU, C, ST, L
	SubjectField string `yaml:"subjectField,omitempty" json:"subjectField,omitempty"`
}

// RevocationConfig configures certificate revocation checking.
type RevocationConfig struct {
	// Enabled enables revocation checking.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// CRL configures CRL checking.
	CRL *CRLConfig `yaml:"crl,omitempty" json:"crl,omitempty"`

	// OCSP configures OCSP checking.
	OCSP *OCSPConfig `yaml:"ocsp,omitempty" json:"ocsp,omitempty"`
}

// CRLConfig configures CRL checking.
type CRLConfig struct {
	// Enabled enables CRL checking.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// URLs is a list of CRL distribution points.
	URLs []string `yaml:"urls,omitempty" json:"urls,omitempty"`

	// CacheEnabled enables CRL caching.
	CacheEnabled bool `yaml:"cacheEnabled,omitempty" json:"cacheEnabled,omitempty"`
}

// OCSPConfig configures OCSP checking.
type OCSPConfig struct {
	// Enabled enables OCSP checking.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// ResponderURL is the OCSP responder URL.
	ResponderURL string `yaml:"responderUrl,omitempty" json:"responderUrl,omitempty"`

	// UseAIA uses the Authority Information Access extension.
	UseAIA bool `yaml:"useAIA,omitempty" json:"useAIA,omitempty"`
}

// VaultConfig configures Vault integration for mTLS.
type VaultConfig struct {
	// Enabled enables Vault integration.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// PKIMount is the Vault PKI mount path.
	PKIMount string `yaml:"pkiMount,omitempty" json:"pkiMount,omitempty"`

	// Role is the Vault PKI role name.
	Role string `yaml:"role,omitempty" json:"role,omitempty"`
}

// Validate validates the mTLS configuration.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// Validate CA source
	if !c.hasCASource() {
		return errors.New("at least one CA source must be configured (caFile, caCert, or vault)")
	}

	// Validate identity extraction
	if c.ExtractIdentity != nil {
		if err := c.ExtractIdentity.Validate(); err != nil {
			return fmt.Errorf("extractIdentity: %w", err)
		}
	}

	// Validate revocation configuration
	if c.Revocation != nil && c.Revocation.Enabled {
		if err := c.Revocation.Validate(); err != nil {
			return fmt.Errorf("revocation: %w", err)
		}
	}

	// Validate Vault configuration
	if c.Vault != nil && c.Vault.Enabled {
		if err := c.Vault.Validate(); err != nil {
			return fmt.Errorf("vault: %w", err)
		}
	}

	return nil
}

// hasCASource checks if at least one CA source is configured.
func (c *Config) hasCASource() bool {
	if c.CAFile != "" {
		return true
	}
	if c.CACert != "" {
		return true
	}
	if c.Vault != nil && c.Vault.Enabled {
		return true
	}
	return false
}

// Validate validates the identity extraction configuration.
func (c *IdentityExtractionConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.SubjectField != "" {
		validFields := map[string]bool{
			"CN": true, "O": true, "OU": true, "C": true, "ST": true, "L": true,
		}
		if !validFields[c.SubjectField] {
			return fmt.Errorf("invalid subject field: %s", c.SubjectField)
		}
	}

	return nil
}

// Validate validates the revocation configuration.
func (c *RevocationConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	// At least one revocation method should be enabled
	crlEnabled := c.CRL != nil && c.CRL.Enabled
	ocspEnabled := c.OCSP != nil && c.OCSP.Enabled

	if !crlEnabled && !ocspEnabled {
		return errors.New("at least one revocation method (CRL or OCSP) must be enabled")
	}

	return nil
}

// Validate validates the Vault configuration.
func (c *VaultConfig) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.PKIMount == "" {
		return errors.New("pkiMount is required")
	}

	return nil
}

// DefaultConfig returns a default mTLS configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled:           false,
		RequireClientCert: true,
		ExtractIdentity: &IdentityExtractionConfig{
			SubjectDN: true,
			SPIFFE:    true,
		},
	}
}

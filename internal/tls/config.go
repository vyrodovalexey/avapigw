package tls

import (
	"crypto/tls"
	"fmt"
	"time"
)

// TLSMode represents the TLS termination mode.
type TLSMode string

// TLS mode constants.
const (
	// TLSModeSimple enables TLS with server certificate only.
	TLSModeSimple TLSMode = "SIMPLE"

	// TLSModeMutual enables mutual TLS (mTLS) requiring client certificates.
	TLSModeMutual TLSMode = "MUTUAL"

	// TLSModeOptionalMutual enables TLS with optional client certificate verification.
	TLSModeOptionalMutual TLSMode = "OPTIONAL_MUTUAL"

	// TLSModePassthrough passes TLS traffic through without termination (SNI routing).
	TLSModePassthrough TLSMode = "PASSTHROUGH"

	// TLSModeAutoPassthrough uses SNI-encoded destination for routing.
	TLSModeAutoPassthrough TLSMode = "AUTO_PASSTHROUGH"

	// TLSModeInsecure disables TLS (plaintext, development only).
	TLSModeInsecure TLSMode = "INSECURE"
)

// String returns the string representation of the TLS mode.
func (m TLSMode) String() string {
	return string(m)
}

// IsValid returns true if the TLS mode is valid.
func (m TLSMode) IsValid() bool {
	switch m {
	case TLSModeSimple, TLSModeMutual, TLSModeOptionalMutual,
		TLSModePassthrough, TLSModeAutoPassthrough, TLSModeInsecure:
		return true
	default:
		return false
	}
}

// RequiresCertificate returns true if the mode requires a server certificate.
func (m TLSMode) RequiresCertificate() bool {
	switch m {
	case TLSModeSimple, TLSModeMutual, TLSModeOptionalMutual:
		return true
	default:
		return false
	}
}

// RequiresClientCA returns true if the mode requires a client CA.
func (m TLSMode) RequiresClientCA() bool {
	switch m {
	case TLSModeMutual, TLSModeOptionalMutual:
		return true
	default:
		return false
	}
}

// TLSVersion represents TLS protocol version.
type TLSVersion string

// TLS version constants.
const (
	// TLSVersionAuto automatically selects the TLS version.
	TLSVersionAuto TLSVersion = "AUTO"

	// TLSVersion10 represents TLS 1.0 (legacy, requires explicit opt-in).
	TLSVersion10 TLSVersion = "TLS10"

	// TLSVersion11 represents TLS 1.1 (legacy, requires explicit opt-in).
	TLSVersion11 TLSVersion = "TLS11"

	// TLSVersion12 represents TLS 1.2 (minimum default).
	TLSVersion12 TLSVersion = "TLS12"

	// TLSVersion13 represents TLS 1.3 (preferred).
	TLSVersion13 TLSVersion = "TLS13"
)

// String returns the string representation of the TLS version.
func (v TLSVersion) String() string {
	return string(v)
}

// IsValid returns true if the TLS version is valid.
func (v TLSVersion) IsValid() bool {
	switch v {
	case TLSVersionAuto, TLSVersion10, TLSVersion11, TLSVersion12, TLSVersion13:
		return true
	default:
		return false
	}
}

// ToTLSVersion converts to crypto/tls version constant.
func (v TLSVersion) ToTLSVersion() uint16 {
	switch v {
	case TLSVersion10:
		return tls.VersionTLS10
	case TLSVersion11:
		return tls.VersionTLS11
	case TLSVersion12:
		return tls.VersionTLS12
	case TLSVersion13:
		return tls.VersionTLS13
	case TLSVersionAuto:
		return 0 // Let Go choose
	default:
		return tls.VersionTLS12 // Safe default
	}
}

// IsLegacy returns true if this is a legacy TLS version (1.0 or 1.1).
func (v TLSVersion) IsLegacy() bool {
	return v == TLSVersion10 || v == TLSVersion11
}

// CertificateSource specifies the certificate source type.
type CertificateSource string

// Certificate source constants.
const (
	// CertificateSourceFile loads certificates from files.
	CertificateSourceFile CertificateSource = "file"

	// CertificateSourceInline uses inline PEM-encoded certificates.
	CertificateSourceInline CertificateSource = "inline"

	// CertificateSourceVault loads certificates from HashiCorp Vault.
	CertificateSourceVault CertificateSource = "vault"
)

// String returns the string representation of the certificate source.
func (s CertificateSource) String() string {
	return string(s)
}

// IsValid returns true if the certificate source is valid.
func (s CertificateSource) IsValid() bool {
	switch s {
	case CertificateSourceFile, CertificateSourceInline, CertificateSourceVault:
		return true
	default:
		return false
	}
}

// Config represents comprehensive TLS configuration.
type Config struct {
	// Mode specifies the TLS termination mode.
	Mode TLSMode `yaml:"mode,omitempty" json:"mode,omitempty"`

	// MinVersion is the minimum TLS version (default: TLS12).
	MinVersion TLSVersion `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version (default: TLS13).
	MaxVersion TLSVersion `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// CurvePreferences is the list of ECDH curves.
	CurvePreferences []string `yaml:"curvePreferences,omitempty" json:"curvePreferences,omitempty"`

	// ServerCertificate configures the server certificate.
	ServerCertificate *CertificateConfig `yaml:"serverCertificate,omitempty" json:"serverCertificate,omitempty"`

	// ClientValidation configures client certificate validation.
	ClientValidation *ClientValidationConfig `yaml:"clientValidation,omitempty" json:"clientValidation,omitempty"`

	// ALPN protocols for negotiation.
	ALPN []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`

	// SessionTicketsDisabled disables session ticket resumption.
	SessionTicketsDisabled bool `yaml:"sessionTicketsDisabled,omitempty" json:"sessionTicketsDisabled,omitempty"`

	// InsecureSkipVerify skips certificate verification (dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// Vault configures Vault-based certificate management.
	Vault *VaultTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// CertificateConfig configures certificate sources.
type CertificateConfig struct {
	// Source specifies where to load certificates from.
	Source CertificateSource `yaml:"source,omitempty" json:"source,omitempty"`

	// CertFile is the path to the certificate file (PEM).
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the private key file (PEM).
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CertData is the PEM-encoded certificate (inline).
	CertData string `yaml:"certData,omitempty" json:"certData,omitempty"`

	// KeyData is the PEM-encoded private key (inline).
	KeyData string `yaml:"keyData,omitempty" json:"keyData,omitempty"`

	// ReloadInterval for hot-reload (0 = disabled).
	ReloadInterval time.Duration `yaml:"reloadInterval,omitempty" json:"reloadInterval,omitempty"`
}

// ClientValidationConfig configures client certificate validation.
type ClientValidationConfig struct {
	// Enabled enables client certificate validation.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// CAFile is the path to the CA certificate file.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// CAData is the PEM-encoded CA certificate (inline).
	CAData string `yaml:"caData,omitempty" json:"caData,omitempty"`

	// VerifyDepth is the maximum certificate chain depth.
	VerifyDepth int `yaml:"verifyDepth,omitempty" json:"verifyDepth,omitempty"`

	// RequireClientCert requires client certificate (for MUTUAL mode).
	RequireClientCert bool `yaml:"requireClientCert,omitempty" json:"requireClientCert,omitempty"`

	// AllowedCNs is the list of allowed Common Names.
	AllowedCNs []string `yaml:"allowedCNs,omitempty" json:"allowedCNs,omitempty"`

	// AllowedSANs is the list of allowed Subject Alternative Names.
	AllowedSANs []string `yaml:"allowedSANs,omitempty" json:"allowedSANs,omitempty"`
}

// VaultTLSConfig configures Vault-based TLS.
type VaultTLSConfig struct {
	// Enabled enables Vault integration.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// PKIMount is the Vault PKI mount path.
	PKIMount string `yaml:"pkiMount,omitempty" json:"pkiMount,omitempty"`

	// Role is the Vault PKI role name.
	Role string `yaml:"role,omitempty" json:"role,omitempty"`

	// CommonName for certificate requests.
	CommonName string `yaml:"commonName,omitempty" json:"commonName,omitempty"`

	// AltNames for certificate requests.
	AltNames []string `yaml:"altNames,omitempty" json:"altNames,omitempty"`

	// TTL for certificate requests.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// RenewBefore is the duration before expiry to renew.
	RenewBefore time.Duration `yaml:"renewBefore,omitempty" json:"renewBefore,omitempty"`
}

// DefaultConfig returns a Config with secure defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:       TLSModeSimple,
		MinVersion: TLSVersion12,
		MaxVersion: TLSVersion13,
		ALPN:       []string{"h2", "http/1.1"},
	}
}

// Validate validates the TLS configuration.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	if err := c.validateMode(); err != nil {
		return err
	}

	if err := c.validateVersions(); err != nil {
		return err
	}

	mode := c.getEffectiveMode()

	if err := c.validateCertificateConfig(mode); err != nil {
		return err
	}

	if err := c.validateClientConfig(mode); err != nil {
		return err
	}

	return c.validateVaultConfig()
}

// validateMode validates the TLS mode.
func (c *Config) validateMode() error {
	if c.Mode != "" && !c.Mode.IsValid() {
		return NewConfigurationError("mode", fmt.Sprintf("invalid TLS mode: %s", c.Mode))
	}
	return nil
}

// validateVersions validates TLS version configuration.
func (c *Config) validateVersions() error {
	if c.MinVersion != "" && !c.MinVersion.IsValid() {
		return NewConfigurationError("minVersion", fmt.Sprintf("invalid TLS version: %s", c.MinVersion))
	}
	if c.MaxVersion != "" && !c.MaxVersion.IsValid() {
		return NewConfigurationError("maxVersion", fmt.Sprintf("invalid TLS version: %s", c.MaxVersion))
	}

	if c.MinVersion != "" && c.MaxVersion != "" {
		minVer := c.MinVersion.ToTLSVersion()
		maxVer := c.MaxVersion.ToTLSVersion()
		if minVer > 0 && maxVer > 0 && minVer > maxVer {
			return NewConfigurationError("minVersion",
				fmt.Sprintf("minVersion (%s) cannot be greater than maxVersion (%s)", c.MinVersion, c.MaxVersion))
		}
	}
	return nil
}

// getEffectiveMode returns the effective TLS mode.
func (c *Config) getEffectiveMode() TLSMode {
	if c.Mode == "" {
		return TLSModeSimple
	}
	return c.Mode
}

// validateCertificateConfig validates certificate configuration for the given mode.
func (c *Config) validateCertificateConfig(mode TLSMode) error {
	if !mode.RequiresCertificate() {
		return nil
	}

	if c.ServerCertificate == nil {
		return NewConfigurationError("serverCertificate", "server certificate required for TLS mode "+string(mode))
	}
	return c.ServerCertificate.Validate()
}

// validateClientConfig validates client validation configuration for the given mode.
func (c *Config) validateClientConfig(mode TLSMode) error {
	if !mode.RequiresClientCA() {
		return nil
	}

	if c.ClientValidation == nil || !c.ClientValidation.Enabled {
		return NewConfigurationError("clientValidation", "client validation required for TLS mode "+string(mode))
	}
	return c.ClientValidation.Validate()
}

// validateVaultConfig validates Vault configuration if enabled.
func (c *Config) validateVaultConfig() error {
	if c.Vault != nil && c.Vault.Enabled {
		return c.Vault.Validate()
	}
	return nil
}

// Validate validates the certificate configuration.
func (c *CertificateConfig) Validate() error {
	if c == nil {
		return NewConfigurationError("serverCertificate", "certificate configuration is nil")
	}

	source := c.Source
	if source == "" {
		source = CertificateSourceFile
	}

	if !source.IsValid() {
		return NewConfigurationError("serverCertificate.source", fmt.Sprintf("invalid certificate source: %s", source))
	}

	switch source {
	case CertificateSourceFile:
		if c.CertFile == "" {
			return NewConfigurationError("serverCertificate.certFile", "certificate file path required")
		}
		if c.KeyFile == "" {
			return NewConfigurationError("serverCertificate.keyFile", "key file path required")
		}
	case CertificateSourceInline:
		if c.CertData == "" {
			return NewConfigurationError("serverCertificate.certData", "certificate data required")
		}
		if c.KeyData == "" {
			return NewConfigurationError("serverCertificate.keyData", "key data required")
		}
	case CertificateSourceVault:
		// Vault config is validated separately
	}

	return nil
}

// Validate validates the client validation configuration.
func (c *ClientValidationConfig) Validate() error {
	if c == nil {
		return nil
	}

	if !c.Enabled {
		return nil
	}

	// Need either CAFile or CAData
	if c.CAFile == "" && c.CAData == "" {
		return NewConfigurationError("clientValidation", "CA file or CA data required for client validation")
	}

	if c.VerifyDepth < 0 {
		return NewConfigurationError("clientValidation.verifyDepth", "verify depth cannot be negative")
	}

	return nil
}

// Validate validates the Vault TLS configuration.
func (c *VaultTLSConfig) Validate() error {
	if c == nil {
		return nil
	}

	if !c.Enabled {
		return nil
	}

	if c.PKIMount == "" {
		return NewConfigurationError("vault.pkiMount", "PKI mount path required")
	}

	if c.Role == "" {
		return NewConfigurationError("vault.role", "PKI role name required")
	}

	if c.CommonName == "" {
		return NewConfigurationError("vault.commonName", "common name required")
	}

	if c.TTL < 0 {
		return NewConfigurationError("vault.ttl", "TTL cannot be negative")
	}

	if c.RenewBefore < 0 {
		return NewConfigurationError("vault.renewBefore", "renewBefore cannot be negative")
	}

	if c.TTL > 0 && c.RenewBefore >= c.TTL {
		return NewConfigurationError("vault.renewBefore", "renewBefore must be less than TTL")
	}

	return nil
}

// GetEffectiveSource returns the effective certificate source.
func (c *CertificateConfig) GetEffectiveSource() CertificateSource {
	if c.Source != "" {
		return c.Source
	}
	// Infer from configuration
	if c.CertData != "" || c.KeyData != "" {
		return CertificateSourceInline
	}
	return CertificateSourceFile
}

// Clone creates a deep copy of the Config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	clone := &Config{
		Mode:                   c.Mode,
		MinVersion:             c.MinVersion,
		MaxVersion:             c.MaxVersion,
		SessionTicketsDisabled: c.SessionTicketsDisabled,
		InsecureSkipVerify:     c.InsecureSkipVerify,
	}

	if len(c.CipherSuites) > 0 {
		clone.CipherSuites = make([]string, len(c.CipherSuites))
		copy(clone.CipherSuites, c.CipherSuites)
	}

	if len(c.CurvePreferences) > 0 {
		clone.CurvePreferences = make([]string, len(c.CurvePreferences))
		copy(clone.CurvePreferences, c.CurvePreferences)
	}

	if len(c.ALPN) > 0 {
		clone.ALPN = make([]string, len(c.ALPN))
		copy(clone.ALPN, c.ALPN)
	}

	if c.ServerCertificate != nil {
		clone.ServerCertificate = c.ServerCertificate.Clone()
	}

	if c.ClientValidation != nil {
		clone.ClientValidation = c.ClientValidation.Clone()
	}

	if c.Vault != nil {
		clone.Vault = c.Vault.Clone()
	}

	return clone
}

// Clone creates a deep copy of the CertificateConfig.
func (c *CertificateConfig) Clone() *CertificateConfig {
	if c == nil {
		return nil
	}

	return &CertificateConfig{
		Source:         c.Source,
		CertFile:       c.CertFile,
		KeyFile:        c.KeyFile,
		CertData:       c.CertData,
		KeyData:        c.KeyData,
		ReloadInterval: c.ReloadInterval,
	}
}

// Clone creates a deep copy of the ClientValidationConfig.
func (c *ClientValidationConfig) Clone() *ClientValidationConfig {
	if c == nil {
		return nil
	}

	clone := &ClientValidationConfig{
		Enabled:           c.Enabled,
		CAFile:            c.CAFile,
		CAData:            c.CAData,
		VerifyDepth:       c.VerifyDepth,
		RequireClientCert: c.RequireClientCert,
	}

	if len(c.AllowedCNs) > 0 {
		clone.AllowedCNs = make([]string, len(c.AllowedCNs))
		copy(clone.AllowedCNs, c.AllowedCNs)
	}

	if len(c.AllowedSANs) > 0 {
		clone.AllowedSANs = make([]string, len(c.AllowedSANs))
		copy(clone.AllowedSANs, c.AllowedSANs)
	}

	return clone
}

// Clone creates a deep copy of the VaultTLSConfig.
func (c *VaultTLSConfig) Clone() *VaultTLSConfig {
	if c == nil {
		return nil
	}

	clone := &VaultTLSConfig{
		Enabled:     c.Enabled,
		PKIMount:    c.PKIMount,
		Role:        c.Role,
		CommonName:  c.CommonName,
		TTL:         c.TTL,
		RenewBefore: c.RenewBefore,
	}

	if len(c.AltNames) > 0 {
		clone.AltNames = make([]string, len(c.AltNames))
		copy(clone.AltNames, c.AltNames)
	}

	return clone
}

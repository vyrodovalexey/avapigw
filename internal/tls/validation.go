package tls

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

// ClientIdentity represents the identity extracted from a client certificate.
type ClientIdentity struct {
	// CommonName is the certificate's Common Name.
	CommonName string

	// DNSNames are the DNS names from the certificate's SAN.
	DNSNames []string

	// IPAddresses are the IP addresses from the certificate's SAN.
	IPAddresses []net.IP

	// EmailAddresses are the email addresses from the certificate's SAN.
	EmailAddresses []string

	// URIs are the URIs from the certificate's SAN.
	URIs []string

	// Organization is the certificate's organization.
	Organization []string

	// OrganizationalUnit is the certificate's organizational unit.
	OrganizationalUnit []string

	// SerialNumber is the certificate's serial number as a string.
	SerialNumber string

	// NotBefore is when the certificate becomes valid.
	NotBefore time.Time

	// NotAfter is when the certificate expires.
	NotAfter time.Time

	// Issuer is the certificate issuer's Common Name.
	Issuer string
}

// ExtractClientIdentity extracts identity information from a client certificate.
func ExtractClientIdentity(cert *x509.Certificate) *ClientIdentity {
	if cert == nil {
		return nil
	}

	identity := &ClientIdentity{
		CommonName:         cert.Subject.CommonName,
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		Issuer:             cert.Issuer.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
	}

	if len(cert.DNSNames) > 0 {
		identity.DNSNames = make([]string, len(cert.DNSNames))
		copy(identity.DNSNames, cert.DNSNames)
	}

	if len(cert.IPAddresses) > 0 {
		identity.IPAddresses = make([]net.IP, len(cert.IPAddresses))
		copy(identity.IPAddresses, cert.IPAddresses)
	}

	if len(cert.EmailAddresses) > 0 {
		identity.EmailAddresses = make([]string, len(cert.EmailAddresses))
		copy(identity.EmailAddresses, cert.EmailAddresses)
	}

	if len(cert.URIs) > 0 {
		identity.URIs = make([]string, len(cert.URIs))
		for i, uri := range cert.URIs {
			identity.URIs[i] = uri.String()
		}
	}

	return identity
}

// Validator provides certificate validation functionality.
type Validator struct {
	config *ClientValidationConfig
}

// NewValidator creates a new certificate validator.
func NewValidator(config *ClientValidationConfig) *Validator {
	return &Validator{config: config}
}

// ValidateClientCertificate validates a client certificate against the configuration.
func (v *Validator) ValidateClientCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return NewValidationError("", "certificate is nil")
	}

	// Check expiration
	if err := v.validateExpiration(cert); err != nil {
		return err
	}

	// Check allowed CNs
	if err := v.validateCommonName(cert); err != nil {
		return err
	}

	// Check allowed SANs
	if err := v.validateSANs(cert); err != nil {
		return err
	}

	return nil
}

// validateExpiration checks if the certificate is within its validity period.
func (v *Validator) validateExpiration(cert *x509.Certificate) error {
	now := time.Now()

	if now.Before(cert.NotBefore) {
		return NewValidationError(
			cert.Subject.CommonName,
			fmt.Sprintf("certificate not yet valid (valid from %s)", cert.NotBefore.Format(time.RFC3339)),
		)
	}

	if now.After(cert.NotAfter) {
		return NewValidationErrorWithCause(
			cert.Subject.CommonName,
			fmt.Sprintf("certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
			ErrCertificateExpired,
		)
	}

	return nil
}

// validateCommonName checks if the certificate's CN is in the allowed list.
func (v *Validator) validateCommonName(cert *x509.Certificate) error {
	if v.config == nil || len(v.config.AllowedCNs) == 0 {
		return nil
	}

	cn := cert.Subject.CommonName
	if cn == "" {
		return NewValidationError("", "certificate has no Common Name")
	}

	for _, allowed := range v.config.AllowedCNs {
		if matchPattern(cn, allowed) {
			return nil
		}
	}

	return NewValidationErrorWithCause(
		cn,
		fmt.Sprintf("Common Name '%s' not in allowed list", cn),
		ErrClientCertNotAllowed,
	)
}

// validateSANs checks if any of the certificate's SANs are in the allowed list.
func (v *Validator) validateSANs(cert *x509.Certificate) error {
	if v.config == nil || len(v.config.AllowedSANs) == 0 {
		return nil
	}

	// Collect all SANs
	sans := collectSANs(cert)

	if len(sans) == 0 {
		return NewValidationError(
			cert.Subject.CommonName,
			"certificate has no Subject Alternative Names",
		)
	}

	// Check if any SAN matches the allowed list
	for _, san := range sans {
		for _, allowed := range v.config.AllowedSANs {
			if matchPattern(san, allowed) {
				return nil
			}
		}
	}

	return NewValidationErrorWithCause(
		cert.Subject.CommonName,
		"no Subject Alternative Name matches allowed list",
		ErrClientCertNotAllowed,
	)
}

// collectSANs collects all Subject Alternative Names from a certificate.
func collectSANs(cert *x509.Certificate) []string {
	// Pre-allocate with estimated capacity
	capacity := len(cert.DNSNames) + len(cert.IPAddresses) + len(cert.EmailAddresses) + len(cert.URIs)
	sans := make([]string, 0, capacity)

	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}

// matchPattern matches a value against a pattern.
// Supports wildcards (*) at the beginning of the pattern.
func matchPattern(value, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		// Wildcard match for subdomains
		suffix := pattern[1:] // Remove the *
		return strings.HasSuffix(value, suffix) || value == pattern[2:]
	}

	return strings.EqualFold(value, pattern)
}

// ValidateCertificateChain validates a certificate chain.
func ValidateCertificateChain(certs []*x509.Certificate, roots *x509.CertPool, opts ...x509.VerifyOptions) error {
	if len(certs) == 0 {
		return NewCertificateError("", "empty certificate chain")
	}

	leaf := certs[0]

	// Build intermediate pool
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	// Apply custom options
	for _, opt := range opts {
		verifyOpts.DNSName = opt.DNSName
		verifyOpts.KeyUsages = opt.KeyUsages
		if opt.CurrentTime != (time.Time{}) {
			verifyOpts.CurrentTime = opt.CurrentTime
		}
	}

	_, err := leaf.Verify(verifyOpts)
	if err != nil {
		return NewCertificateErrorWithCause("", "certificate chain verification failed", err)
	}

	return nil
}

// CertificateExpirationStatus contains the expiration status of a certificate.
type CertificateExpirationStatus struct {
	Expired         bool
	ExpiringSoon    bool
	TimeUntilExpiry time.Duration
}

// CheckCertificateExpiration checks if a certificate is expired or expiring soon.
func CheckCertificateExpiration(
	cert *x509.Certificate,
	warningThreshold time.Duration,
) (expired bool, expiringSoon bool, timeUntilExpiry time.Duration) {
	status := CheckCertificateExpirationStatus(cert, warningThreshold)
	return status.Expired, status.ExpiringSoon, status.TimeUntilExpiry
}

// CheckCertificateExpirationStatus checks certificate expiration and returns a status struct.
func CheckCertificateExpirationStatus(
	cert *x509.Certificate,
	warningThreshold time.Duration,
) CertificateExpirationStatus {
	if cert == nil {
		return CertificateExpirationStatus{Expired: true}
	}

	now := time.Now()
	timeUntilExpiry := cert.NotAfter.Sub(now)

	if now.After(cert.NotAfter) {
		return CertificateExpirationStatus{
			Expired:         true,
			TimeUntilExpiry: timeUntilExpiry,
		}
	}

	if timeUntilExpiry <= warningThreshold {
		return CertificateExpirationStatus{
			ExpiringSoon:    true,
			TimeUntilExpiry: timeUntilExpiry,
		}
	}

	return CertificateExpirationStatus{TimeUntilExpiry: timeUntilExpiry}
}

// IsSelfSigned checks if a certificate is self-signed.
func IsSelfSigned(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}

	// Check if issuer equals subject
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}

	// Verify signature
	err := cert.CheckSignatureFrom(cert)
	return err == nil
}

// GetCertificateFingerprint returns the SHA-256 fingerprint of a certificate.
func GetCertificateFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}

	// Use the raw certificate bytes for fingerprint
	hash := sha256Sum(cert.Raw)
	return formatFingerprint(hash)
}

// sha256Sum computes SHA-256 hash.
func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// formatFingerprint formats a hash as a colon-separated hex string.
func formatFingerprint(hash []byte) string {
	if len(hash) == 0 {
		return ""
	}

	parts := make([]string, len(hash))
	for i, b := range hash {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// ValidateCertificateForHost validates that a certificate is valid for a given hostname.
func ValidateCertificateForHost(cert *x509.Certificate, host string) error {
	if cert == nil {
		return NewCertificateError("", "certificate is nil")
	}

	if host == "" {
		return nil
	}

	// Check if host matches any DNS name
	for _, dnsName := range cert.DNSNames {
		if matchHostname(host, dnsName) {
			return nil
		}
	}

	// Check if host matches CN (legacy behavior)
	if matchHostname(host, cert.Subject.CommonName) {
		return nil
	}

	// Check if host is an IP address
	if ip := net.ParseIP(host); ip != nil {
		for _, certIP := range cert.IPAddresses {
			if ip.Equal(certIP) {
				return nil
			}
		}
	}

	return NewCertificateError(
		cert.Subject.CommonName,
		fmt.Sprintf("certificate is not valid for host '%s'", host),
	)
}

// matchHostname matches a hostname against a pattern (supports wildcards).
func matchHostname(host, pattern string) bool {
	if pattern == "" {
		return false
	}

	// Exact match
	if strings.EqualFold(host, pattern) {
		return true
	}

	// Wildcard match
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // Keep the dot
		// Host must have at least one subdomain
		if idx := strings.Index(host, "."); idx > 0 {
			hostSuffix := host[idx:]
			return strings.EqualFold(hostSuffix, suffix)
		}
	}

	return false
}

// CertificateChainInfo contains information about a certificate chain.
type CertificateChainInfo struct {
	// Leaf is the leaf certificate info.
	Leaf *CertificateInfo

	// Intermediates are the intermediate certificate infos.
	Intermediates []*CertificateInfo

	// Root is the root certificate info (if present in chain).
	Root *CertificateInfo

	// ChainLength is the total number of certificates in the chain.
	ChainLength int

	// IsComplete indicates if the chain is complete (ends with a root).
	IsComplete bool
}

// AnalyzeCertificateChain analyzes a certificate chain and returns information about it.
func AnalyzeCertificateChain(certs []*x509.Certificate) *CertificateChainInfo {
	if len(certs) == 0 {
		return nil
	}

	info := &CertificateChainInfo{
		ChainLength: len(certs),
	}

	// First cert is the leaf
	info.Leaf = ExtractCertificateInfo(certs[0])

	// Check intermediates and root
	for i := 1; i < len(certs); i++ {
		cert := certs[i]
		certInfo := ExtractCertificateInfo(cert)

		if IsSelfSigned(cert) {
			info.Root = certInfo
			info.IsComplete = true
		} else {
			info.Intermediates = append(info.Intermediates, certInfo)
		}
	}

	return info
}

// FilterExpiredCertificates filters out expired certificates from a list.
func FilterExpiredCertificates(certs []*x509.Certificate) []*x509.Certificate {
	now := time.Now()
	valid := make([]*x509.Certificate, 0, len(certs))

	for _, cert := range certs {
		if cert != nil && now.Before(cert.NotAfter) && now.After(cert.NotBefore) {
			valid = append(valid, cert)
		}
	}

	return valid
}

// SortCertificatesByExpiry sorts certificates by expiry date (earliest first).
func SortCertificatesByExpiry(certs []*x509.Certificate) {
	slices.SortFunc(certs, func(a, b *x509.Certificate) int {
		if a.NotAfter.Before(b.NotAfter) {
			return -1
		}
		if a.NotAfter.After(b.NotAfter) {
			return 1
		}
		return 0
	})
}

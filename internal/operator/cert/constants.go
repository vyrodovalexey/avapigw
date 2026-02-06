// Package cert provides certificate management for the operator.
package cert

import "time"

// Certificate configuration constants for the self-signed certificate provider.
// These values define the default certificate lifecycle and security parameters.
const (
	// DefaultCACommonName is the default common name for the CA certificate.
	DefaultCACommonName = "avapigw-operator-ca"

	// DefaultCAValidity is the default validity period for the CA certificate (1 year).
	DefaultCAValidity = 365 * 24 * time.Hour

	// DefaultCertValidity is the default validity period for issued certificates (30 days).
	DefaultCertValidity = 30 * 24 * time.Hour

	// DefaultRotateBefore is the default duration before expiry to rotate certificates (7 days).
	DefaultRotateBefore = 7 * 24 * time.Hour

	// DefaultKeySize is the default RSA key size in bits.
	// 4096 bits provides strong security for production use.
	DefaultKeySize = 4096

	// DefaultOrganization is the default organization for certificates.
	DefaultOrganization = "avapigw"

	// DefaultSecretName is the default name of the Kubernetes secret to store certificates.
	DefaultSecretName = "avapigw-operator-certs"

	// DefaultSecretNamespace is the default namespace of the Kubernetes secret.
	DefaultSecretNamespace = "avapigw-system"
)

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// TLSConfig CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=tlsc
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="NotAfter",type="string",JSONPath=".status.certificate.notAfter"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// TLSConfig is the Schema for the tlsconfigs API.
// TLSConfig defines TLS certificate configuration.
type TLSConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TLSConfigSpec   `json:"spec,omitempty"`
	Status TLSConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TLSConfigList contains a list of TLSConfig
type TLSConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSConfig `json:"items"`
}

// TLSConfigSpec defines the desired state of TLSConfig
type TLSConfigSpec struct {
	// CertificateSource defines the source of the TLS certificate.
	// +kubebuilder:validation:Required
	CertificateSource CertificateSource `json:"certificateSource"`

	// MinVersion is the minimum TLS version.
	// +kubebuilder:validation:Enum=TLS10;TLS11;TLS12;TLS13
	// +kubebuilder:default=TLS12
	// +optional
	MinVersion *TLSVersion `json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	// +kubebuilder:validation:Enum=TLS10;TLS11;TLS12;TLS13
	// +kubebuilder:default=TLS13
	// +optional
	MaxVersion *TLSVersion `json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	CipherSuites []string `json:"cipherSuites,omitempty"`

	// ALPNProtocols is the list of ALPN protocols.
	// +kubebuilder:validation:MaxItems=8
	// +optional
	ALPNProtocols []string `json:"alpnProtocols,omitempty"`

	// ClientValidation defines client certificate validation (mTLS).
	// +optional
	ClientValidation *ClientValidationConfig `json:"clientValidation,omitempty"`

	// Rotation defines certificate rotation configuration.
	// +optional
	Rotation *CertificateRotationConfig `json:"rotation,omitempty"`
}

// TLSVersion defines TLS version
// +kubebuilder:validation:Enum=TLS10;TLS11;TLS12;TLS13
type TLSVersion string

const (
	// TLSVersion10 is TLS 1.0
	TLSVersion10 TLSVersion = "TLS10"
	// TLSVersion11 is TLS 1.1
	TLSVersion11 TLSVersion = "TLS11"
	// TLSVersion12 is TLS 1.2
	TLSVersion12 TLSVersion = "TLS12"
	// TLSVersion13 is TLS 1.3
	TLSVersion13 TLSVersion = "TLS13"
)

// CertificateSource defines the source of a TLS certificate
type CertificateSource struct {
	// Secret references a Kubernetes Secret containing the certificate.
	// +optional
	Secret *SecretCertificateSource `json:"secret,omitempty"`

	// Vault references a Vault path containing the certificate.
	// +optional
	Vault *VaultCertificateSource `json:"vault,omitempty"`
}

// SecretCertificateSource defines a Secret as the certificate source
type SecretCertificateSource struct {
	// Name is the name of the Secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the Secret.
	// If not specified, the namespace of the TLSConfig is used.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// CertKey is the key in the Secret containing the certificate.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="tls.crt"
	// +optional
	CertKey *string `json:"certKey,omitempty"`

	// KeyKey is the key in the Secret containing the private key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="tls.key"
	// +optional
	KeyKey *string `json:"keyKey,omitempty"`

	// CAKey is the key in the Secret containing the CA certificate.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	CAKey *string `json:"caKey,omitempty"`
}

// VaultCertificateSource defines Vault as the certificate source
type VaultCertificateSource struct {
	// Path is the Vault path to the certificate.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Path string `json:"path"`

	// MountPoint is the Vault mount point.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="secret"
	// +optional
	MountPoint *string `json:"mountPoint,omitempty"`

	// VaultSecretRef references a VaultSecret for connection details.
	// +optional
	VaultSecretRef *LocalObjectReference `json:"vaultSecretRef,omitempty"`

	// CertKey is the key in the Vault secret containing the certificate.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="certificate"
	// +optional
	CertKey *string `json:"certKey,omitempty"`

	// KeyKey is the key in the Vault secret containing the private key.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="private_key"
	// +optional
	KeyKey *string `json:"keyKey,omitempty"`

	// CAKey is the key in the Vault secret containing the CA certificate.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +optional
	CAKey *string `json:"caKey,omitempty"`
}

// ClientValidationConfig defines client certificate validation configuration
type ClientValidationConfig struct {
	// Enabled indicates whether client validation is enabled.
	// +kubebuilder:default=false
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Mode defines the client validation mode.
	// +kubebuilder:validation:Enum=Required;Optional
	// +kubebuilder:default=Required
	// +optional
	Mode *ClientValidationMode `json:"mode,omitempty"`

	// CACertificateRef references a Secret containing the CA certificate.
	// +optional
	CACertificateRef *SecretObjectReference `json:"caCertificateRef,omitempty"`

	// SubjectAltNames defines allowed subject alternative names.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	SubjectAltNames []SubjectAltNameMatch `json:"subjectAltNames,omitempty"`

	// TrustedCAs is a list of trusted CA certificates.
	// +kubebuilder:validation:MaxItems=16
	// +optional
	TrustedCAs []SecretObjectReference `json:"trustedCAs,omitempty"`
}

// ClientValidationMode defines the client validation mode
// +kubebuilder:validation:Enum=Required;Optional
type ClientValidationMode string

const (
	// ClientValidationRequired requires client certificates
	ClientValidationRequired ClientValidationMode = "Required"
	// ClientValidationOptional makes client certificates optional
	ClientValidationOptional ClientValidationMode = "Optional"
)

// SubjectAltNameMatch defines a subject alternative name match
type SubjectAltNameMatch struct {
	// Exact is an exact SAN match.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Exact *string `json:"exact,omitempty"`

	// Prefix is a prefix SAN match.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Prefix *string `json:"prefix,omitempty"`

	// Suffix is a suffix SAN match.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Suffix *string `json:"suffix,omitempty"`

	// Regex is a regex SAN match.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Regex *string `json:"regex,omitempty"`
}

// CertificateRotationConfig defines certificate rotation configuration
type CertificateRotationConfig struct {
	// Enabled indicates whether automatic rotation is enabled.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// CheckInterval is the interval to check for certificate expiration.
	// +kubebuilder:default="1h"
	// +optional
	CheckInterval *Duration `json:"checkInterval,omitempty"`

	// RenewBefore is the duration before expiration to renew the certificate.
	// +kubebuilder:validation:Pattern=`^([0-9]+(h|d))+$`
	// +kubebuilder:default="720h"
	// +optional
	RenewBefore *string `json:"renewBefore,omitempty"`
}

// ============================================================================
// TLSConfig Status
// ============================================================================

// TLSConfigStatus defines the observed state of TLSConfig
type TLSConfigStatus struct {
	Status `json:",inline"`

	// Certificate contains information about the loaded certificate.
	// +optional
	Certificate *CertificateInfo `json:"certificate,omitempty"`
}

// CertificateInfo contains information about a certificate
type CertificateInfo struct {
	// NotBefore is the certificate's not before time.
	// +optional
	NotBefore *metav1.Time `json:"notBefore,omitempty"`

	// NotAfter is the certificate's not after time.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`

	// Issuer is the certificate issuer.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Issuer *string `json:"issuer,omitempty"`

	// Subject is the certificate subject.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Subject *string `json:"subject,omitempty"`

	// DNSNames is the list of DNS names in the certificate.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// SerialNumber is the certificate serial number.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	SerialNumber *string `json:"serialNumber,omitempty"`

	// Fingerprint is the SHA-256 fingerprint of the certificate.
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Fingerprint *string `json:"fingerprint,omitempty"`
}

func init() {
	SchemeBuilder.Register(&TLSConfig{}, &TLSConfigList{})
}

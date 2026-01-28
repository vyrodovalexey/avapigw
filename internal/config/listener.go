package config

import "time"

// Listener represents a network listener configuration.
type Listener struct {
	Name     string              `yaml:"name" json:"name"`
	Port     int                 `yaml:"port" json:"port"`
	Protocol string              `yaml:"protocol" json:"protocol"`
	Hosts    []string            `yaml:"hosts,omitempty" json:"hosts,omitempty"`
	Bind     string              `yaml:"bind,omitempty" json:"bind,omitempty"`
	GRPC     *GRPCListenerConfig `yaml:"grpc,omitempty" json:"grpc,omitempty"`
	TLS      *ListenerTLSConfig  `yaml:"tls,omitempty" json:"tls,omitempty"`
	Timeouts *ListenerTimeouts   `yaml:"timeouts,omitempty" json:"timeouts,omitempty"`
}

// ListenerTimeouts contains timeout configuration for HTTP listeners.
type ListenerTimeouts struct {
	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	ReadTimeout Duration `yaml:"readTimeout,omitempty" json:"readTimeout,omitempty"`

	// ReadHeaderTimeout is the maximum duration for reading request headers.
	ReadHeaderTimeout Duration `yaml:"readHeaderTimeout,omitempty" json:"readHeaderTimeout,omitempty"`

	// WriteTimeout is the maximum duration before timing out writes of the response.
	WriteTimeout Duration `yaml:"writeTimeout,omitempty" json:"writeTimeout,omitempty"`

	// IdleTimeout is the maximum duration to wait for the next request when keep-alives are enabled.
	IdleTimeout Duration `yaml:"idleTimeout,omitempty" json:"idleTimeout,omitempty"`
}

// DefaultListenerTimeouts returns the default listener timeout configuration.
func DefaultListenerTimeouts() *ListenerTimeouts {
	return &ListenerTimeouts{
		ReadTimeout:       Duration(DefaultReadTimeout),
		ReadHeaderTimeout: Duration(DefaultReadHeaderTimeout),
		WriteTimeout:      Duration(DefaultWriteTimeout),
		IdleTimeout:       Duration(DefaultIdleTimeout),
	}
}

// GetEffectiveReadTimeout returns the effective read timeout.
func (t *ListenerTimeouts) GetEffectiveReadTimeout() time.Duration {
	if t == nil || t.ReadTimeout == 0 {
		return DefaultReadTimeout
	}
	return t.ReadTimeout.Duration()
}

// GetEffectiveReadHeaderTimeout returns the effective read header timeout.
func (t *ListenerTimeouts) GetEffectiveReadHeaderTimeout() time.Duration {
	if t == nil || t.ReadHeaderTimeout == 0 {
		return DefaultReadHeaderTimeout
	}
	return t.ReadHeaderTimeout.Duration()
}

// GetEffectiveWriteTimeout returns the effective write timeout.
func (t *ListenerTimeouts) GetEffectiveWriteTimeout() time.Duration {
	if t == nil || t.WriteTimeout == 0 {
		return DefaultWriteTimeout
	}
	return t.WriteTimeout.Duration()
}

// GetEffectiveIdleTimeout returns the effective idle timeout.
func (t *ListenerTimeouts) GetEffectiveIdleTimeout() time.Duration {
	if t == nil || t.IdleTimeout == 0 {
		return DefaultIdleTimeout
	}
	return t.IdleTimeout.Duration()
}

// ListenerTLSConfig contains TLS configuration for HTTP/HTTPS listeners.
type ListenerTLSConfig struct {
	// Mode specifies the TLS mode (SIMPLE, MUTUAL, OPTIONAL_MUTUAL, PASSTHROUGH, INSECURE).
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// MinVersion is the minimum TLS version (TLS12, TLS13).
	MinVersion string `yaml:"minVersion,omitempty" json:"minVersion,omitempty"`

	// MaxVersion is the maximum TLS version.
	MaxVersion string `yaml:"maxVersion,omitempty" json:"maxVersion,omitempty"`

	// CipherSuites is the list of allowed cipher suites.
	CipherSuites []string `yaml:"cipherSuites,omitempty" json:"cipherSuites,omitempty"`

	// CertFile is the path to the server certificate.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the server private key.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to the CA certificate for client validation.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`

	// RequireClientCert requires client certificate (for MUTUAL mode).
	RequireClientCert bool `yaml:"requireClientCert,omitempty" json:"requireClientCert,omitempty"`

	// InsecureSkipVerify skips certificate verification (dev only).
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify,omitempty"`

	// ALPN protocols for negotiation.
	ALPN []string `yaml:"alpn,omitempty" json:"alpn,omitempty"`

	// HTTPSRedirect enables automatic HTTP to HTTPS redirect.
	HTTPSRedirect bool `yaml:"httpsRedirect,omitempty" json:"httpsRedirect,omitempty"`

	// HSTS configures HTTP Strict Transport Security.
	HSTS *HSTSConfig `yaml:"hsts,omitempty" json:"hsts,omitempty"`

	// Vault configures Vault-based certificate management.
	Vault *VaultTLSConfig `yaml:"vault,omitempty" json:"vault,omitempty"`
}

// HSTSConfig configures HTTP Strict Transport Security.
type HSTSConfig struct {
	// Enabled enables HSTS header.
	Enabled bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// MaxAge is the max-age directive value in seconds.
	MaxAge int `yaml:"maxAge,omitempty" json:"maxAge,omitempty"`

	// IncludeSubDomains includes the includeSubDomains directive.
	IncludeSubDomains bool `yaml:"includeSubDomains,omitempty" json:"includeSubDomains,omitempty"`

	// Preload includes the preload directive.
	Preload bool `yaml:"preload,omitempty" json:"preload,omitempty"`
}

// VaultTLSConfig configures Vault-based TLS for listeners.
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
	TTL string `yaml:"ttl,omitempty" json:"ttl,omitempty"`
}

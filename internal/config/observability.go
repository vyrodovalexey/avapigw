package config

import (
	"net"
	"strings"
)

// ObservabilityConfig represents observability configuration.
type ObservabilityConfig struct {
	Metrics *MetricsConfig `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	Tracing *TracingConfig `yaml:"tracing,omitempty" json:"tracing,omitempty"`
	Logging *LoggingConfig `yaml:"logging,omitempty" json:"logging,omitempty"`
}

// MetricsConfig represents metrics configuration.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path,omitempty" json:"path,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
}

// TracingConfig represents tracing configuration.
type TracingConfig struct {
	Enabled      bool    `yaml:"enabled" json:"enabled"`
	SamplingRate float64 `yaml:"samplingRate,omitempty" json:"samplingRate,omitempty"`
	OTLPEndpoint string  `yaml:"otlpEndpoint,omitempty" json:"otlpEndpoint,omitempty"`
	ServiceName  string  `yaml:"serviceName,omitempty" json:"serviceName,omitempty"`

	// OTLPInsecure controls whether the OTLP gRPC exporter uses plaintext.
	// Tri-state: when nil, the effective transport security is derived by
	// EffectiveOTLPInsecure (TLS material forces TLS; otherwise plaintext is
	// retained only for unset/loopback endpoints and remote endpoints
	// default to TLS with system roots).
	OTLPInsecure *bool `yaml:"otlpInsecure,omitempty" json:"otlpInsecure,omitempty"`

	// OTLPTLS configures TLS material for the OTLP exporter connection
	// (client certificate for mTLS and/or a private CA bundle).
	OTLPTLS *OTLPTLSConfig `yaml:"otlpTLS,omitempty" json:"otlpTLS,omitempty"`
}

// OTLPTLSConfig configures TLS material for the OTLP trace exporter
// connection to the collector.
type OTLPTLSConfig struct {
	// CertFile is the path to the client certificate (PEM) for mTLS to the
	// OTLP collector. Requires KeyFile.
	CertFile string `yaml:"certFile,omitempty" json:"certFile,omitempty"`

	// KeyFile is the path to the client private key (PEM) for mTLS to the
	// OTLP collector. Requires CertFile.
	KeyFile string `yaml:"keyFile,omitempty" json:"keyFile,omitempty"`

	// CAFile is the path to a PEM CA bundle used to verify the OTLP
	// collector certificate. Empty uses the system trust store.
	CAFile string `yaml:"caFile,omitempty" json:"caFile,omitempty"`
}

// IsEmpty reports whether no TLS material is configured (nil-safe).
func (c *OTLPTLSConfig) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.CertFile == "" && c.KeyFile == "" && c.CAFile == ""
}

// EffectiveOTLPInsecure resolves the OTLP exporter transport security:
//
//  1. an explicit otlpInsecure value always wins;
//  2. configured otlpTLS material forces TLS;
//  3. otherwise plaintext is retained only when the endpoint is unset or
//     plainly local (loopback), preserving the historical default for local
//     collectors; remote endpoints default to TLS with system roots.
func (c *TracingConfig) EffectiveOTLPInsecure() bool {
	if c == nil {
		return true
	}
	if c.OTLPInsecure != nil {
		return *c.OTLPInsecure
	}
	if !c.OTLPTLS.IsEmpty() {
		return false
	}
	return isLocalOTLPEndpoint(c.OTLPEndpoint)
}

// isLocalOTLPEndpoint reports whether the OTLP endpoint is unset or targets
// a loopback address, where the historical plaintext default is preserved.
func isLocalOTLPEndpoint(endpoint string) bool {
	host := otlpEndpointHost(endpoint)
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// otlpEndpointHost extracts the host portion from an OTLP endpoint, which
// may be "host:port", a bare host, or carry an http(s):// scheme prefix.
func otlpEndpointHost(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	for _, scheme := range []string{"https://", "http://", "grpc://", "dns://"} {
		if rest, ok := strings.CutPrefix(endpoint, scheme); ok {
			endpoint = rest
			break
		}
	}
	if slash := strings.IndexByte(endpoint, '/'); slash >= 0 {
		endpoint = endpoint[:slash]
	}
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return strings.Trim(endpoint, "[]")
}

// LoggingConfig represents logging configuration.
type LoggingConfig struct {
	Level  string `yaml:"level,omitempty" json:"level,omitempty"`
	Format string `yaml:"format,omitempty" json:"format,omitempty"`
	Output string `yaml:"output,omitempty" json:"output,omitempty"`
}

package listener

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
)

// CertificateManager manages TLS certificates with hot-reload support.
type CertificateManager struct {
	certFile string
	keyFile  string
	caFile   string
	cert     *tls.Certificate
	caPool   *x509.CertPool
	mu       sync.RWMutex
	logger   *zap.Logger
}

// NewCertificateManager creates a new certificate manager.
func NewCertificateManager(certFile, keyFile, caFile string, logger *zap.Logger) (*CertificateManager, error) {
	cm := &CertificateManager{
		certFile: certFile,
		keyFile:  keyFile,
		caFile:   caFile,
		logger:   logger,
	}

	if err := cm.loadCertificates(); err != nil {
		return nil, err
	}

	return cm, nil
}

// loadCertificates loads certificates from files.
func (cm *CertificateManager) loadCertificates() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Load server certificate
	if cm.certFile != "" && cm.keyFile != "" {
		cert, err := tls.LoadX509KeyPair(cm.certFile, cm.keyFile)
		if err != nil {
			return fmt.Errorf("failed to load certificate: %w", err)
		}
		cm.cert = &cert
		cm.logger.Info("loaded TLS certificate",
			zap.String("certFile", cm.certFile),
			zap.String("keyFile", cm.keyFile),
		)
	}

	// Load CA certificate
	if cm.caFile != "" {
		caCert, err := os.ReadFile(cm.caFile)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %w", err)
		}

		cm.caPool = x509.NewCertPool()
		if !cm.caPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		cm.logger.Info("loaded CA certificate", zap.String("caFile", cm.caFile))
	}

	return nil
}

// Reload reloads certificates from files.
func (cm *CertificateManager) Reload() error {
	cm.logger.Info("reloading TLS certificates")
	return cm.loadCertificates()
}

// GetCertificate returns the current certificate for TLS config.
func (cm *CertificateManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.cert == nil {
		return nil, fmt.Errorf("no certificate loaded")
	}

	return cm.cert, nil
}

// GetCAPool returns the CA certificate pool.
func (cm *CertificateManager) GetCAPool() *x509.CertPool {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.caPool
}

// LoadTLSConfig creates a tls.Config from TLSConfig.
func LoadTLSConfig(config *TLSConfig) (*tls.Config, error) {
	if config == nil {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: config.MinVersion,
		MaxVersion: config.MaxVersion,
	}

	// Set default versions if not specified
	if tlsConfig.MinVersion == 0 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	if tlsConfig.MaxVersion == 0 {
		tlsConfig.MaxVersion = tls.VersionTLS13
	}

	// Load certificate
	if config.CertFile != "" && config.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate
	if config.CAFile != "" {
		caCert, err := os.ReadFile(config.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.ClientCAs = caPool
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsConfig, nil
}

// CreateTLSConfigWithManager creates a tls.Config that uses CertificateManager for hot-reload.
func CreateTLSConfigWithManager(cm *CertificateManager) *tls.Config {
	return &tls.Config{
		GetCertificate: cm.GetCertificate,
		ClientCAs:      cm.GetCAPool(),
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
	}
}

// DefaultTLSConfig returns a secure default TLS configuration.
func DefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}

// MergeTLSConfig merges a custom TLS config with secure defaults.
func MergeTLSConfig(custom *tls.Config) *tls.Config {
	defaults := DefaultTLSConfig()

	if custom == nil {
		return defaults
	}

	// Use custom certificates if provided
	if len(custom.Certificates) > 0 {
		defaults.Certificates = custom.Certificates
	}
	if custom.GetCertificate != nil {
		defaults.GetCertificate = custom.GetCertificate
	}

	// Use custom CA pool if provided
	if custom.ClientCAs != nil {
		defaults.ClientCAs = custom.ClientCAs
	}
	if custom.RootCAs != nil {
		defaults.RootCAs = custom.RootCAs
	}

	// Use custom client auth if set
	if custom.ClientAuth != tls.NoClientCert {
		defaults.ClientAuth = custom.ClientAuth
	}

	// Use custom versions if set
	if custom.MinVersion != 0 {
		defaults.MinVersion = custom.MinVersion
	}
	if custom.MaxVersion != 0 {
		defaults.MaxVersion = custom.MaxVersion
	}

	return defaults
}

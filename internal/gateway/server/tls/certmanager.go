// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// CertificateManager manages TLS certificates with hot-reload support.
type CertificateManager struct {
	certificates map[string]*tls.Certificate // keyed by hostname
	defaultCert  *tls.Certificate
	mu           sync.RWMutex
	logger       *zap.Logger
	watcher      *fsnotify.Watcher
	watchedFiles map[string]certificateFiles
	stopCh       chan struct{}
}

// certificateFiles tracks the files for a certificate.
type certificateFiles struct {
	hostname string
	certFile string
	keyFile  string
}

// NewCertificateManager creates a new certificate manager.
func NewCertificateManager(logger *zap.Logger) *CertificateManager {
	return &CertificateManager{
		certificates: make(map[string]*tls.Certificate),
		logger:       logger,
		watchedFiles: make(map[string]certificateFiles),
		stopCh:       make(chan struct{}),
	}
}

// LoadCertificate loads a certificate from files for a specific hostname.
func (m *CertificateManager) LoadCertificate(hostname, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate for %s: %w", hostname, err)
	}

	m.mu.Lock()
	m.certificates[hostname] = &cert
	m.watchedFiles[hostname] = certificateFiles{
		hostname: hostname,
		certFile: certFile,
		keyFile:  keyFile,
	}
	m.mu.Unlock()

	m.logger.Info("certificate loaded",
		zap.String("hostname", hostname),
		zap.String("certFile", certFile),
		zap.String("keyFile", keyFile),
	)

	return nil
}

// LoadCertificateFromSecret loads a certificate from raw data (e.g., from Kubernetes Secret).
func (m *CertificateManager) LoadCertificateFromSecret(hostname string, certData, keyData []byte) error {
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for %s: %w", hostname, err)
	}

	m.mu.Lock()
	m.certificates[hostname] = &cert
	m.mu.Unlock()

	m.logger.Info("certificate loaded from secret",
		zap.String("hostname", hostname),
	)

	return nil
}

// GetCertificate returns the certificate for a TLS ClientHello.
// This implements the tls.Config.GetCertificate callback.
func (m *CertificateManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	serverName := hello.ServerName

	// Try exact match first
	if cert, ok := m.certificates[serverName]; ok {
		m.logger.Debug("certificate found for hostname",
			zap.String("hostname", serverName),
		)
		return cert, nil
	}

	// Try wildcard match
	if cert := m.findWildcardCert(serverName); cert != nil {
		m.logger.Debug("wildcard certificate found for hostname",
			zap.String("hostname", serverName),
		)
		return cert, nil
	}

	// Return default certificate if available
	if m.defaultCert != nil {
		m.logger.Debug("using default certificate for hostname",
			zap.String("hostname", serverName),
		)
		return m.defaultCert, nil
	}

	return nil, fmt.Errorf("no certificate found for %s", serverName)
}

// findWildcardCert finds a wildcard certificate that matches the hostname.
func (m *CertificateManager) findWildcardCert(hostname string) *tls.Certificate {
	// Extract domain parts
	parts := splitHostname(hostname)
	if len(parts) < 2 {
		return nil
	}

	// Try wildcard pattern (e.g., *.example.com for foo.example.com)
	wildcardPattern := "*." + joinHostname(parts[1:])
	if cert, ok := m.certificates[wildcardPattern]; ok {
		return cert
	}

	return nil
}

// splitHostname splits a hostname into parts.
func splitHostname(hostname string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(hostname); i++ {
		if hostname[i] == '.' {
			parts = append(parts, hostname[start:i])
			start = i + 1
		}
	}
	if start < len(hostname) {
		parts = append(parts, hostname[start:])
	}
	return parts
}

// joinHostname joins hostname parts.
func joinHostname(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "." + parts[i]
	}
	return result
}

// SetDefaultCertificate sets the default certificate to use when no hostname matches.
func (m *CertificateManager) SetDefaultCertificate(cert *tls.Certificate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.defaultCert = cert
	m.logger.Info("default certificate set")
}

// SetDefaultCertificateFromFiles loads and sets the default certificate from files.
func (m *CertificateManager) SetDefaultCertificateFromFiles(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load default certificate: %w", err)
	}

	m.mu.Lock()
	m.defaultCert = &cert
	m.mu.Unlock()

	m.logger.Info("default certificate loaded",
		zap.String("certFile", certFile),
		zap.String("keyFile", keyFile),
	)

	return nil
}

// RemoveCertificate removes a certificate for a hostname.
func (m *CertificateManager) RemoveCertificate(hostname string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.certificates, hostname)
	delete(m.watchedFiles, hostname)

	m.logger.Info("certificate removed", zap.String("hostname", hostname))
}

// ListCertificates returns all hostnames with loaded certificates.
func (m *CertificateManager) ListCertificates() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hostnames := make([]string, 0, len(m.certificates))
	for hostname := range m.certificates {
		hostnames = append(hostnames, hostname)
	}
	return hostnames
}

// WatchCertificates starts watching certificate files for changes.
func (m *CertificateManager) WatchCertificates(stopCh <-chan struct{}) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	m.mu.Lock()
	m.watcher = watcher
	m.mu.Unlock()

	// Add watched files
	m.mu.RLock()
	for _, files := range m.watchedFiles {
		// Watch the directory containing the certificate files
		certDir := filepath.Dir(files.certFile)
		keyDir := filepath.Dir(files.keyFile)

		if err := watcher.Add(certDir); err != nil {
			m.logger.Warn("failed to watch certificate directory",
				zap.String("dir", certDir),
				zap.Error(err),
			)
		}
		if certDir != keyDir {
			if err := watcher.Add(keyDir); err != nil {
				m.logger.Warn("failed to watch key directory",
					zap.String("dir", keyDir),
					zap.Error(err),
				)
			}
		}
	}
	m.mu.RUnlock()

	// Start watching
	go m.watchLoop(stopCh)

	m.logger.Info("certificate file watching started")
	return nil
}

// watchLoop handles file system events.
func (m *CertificateManager) watchLoop(stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			m.logger.Info("certificate file watching stopped")
			if m.watcher != nil {
				_ = m.watcher.Close() // Ignore error on cleanup
			}
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				m.handleFileChange(event.Name)
			}
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.logger.Error("file watcher error", zap.Error(err))
		}
	}
}

// handleFileChange handles a certificate file change.
func (m *CertificateManager) handleFileChange(filename string) {
	m.mu.RLock()
	var toReload []certificateFiles
	for _, files := range m.watchedFiles {
		if files.certFile == filename || files.keyFile == filename {
			toReload = append(toReload, files)
		}
	}
	m.mu.RUnlock()

	for _, files := range toReload {
		m.logger.Info("reloading certificate",
			zap.String("hostname", files.hostname),
			zap.String("changedFile", filename),
		)

		if err := m.LoadCertificate(files.hostname, files.certFile, files.keyFile); err != nil {
			m.logger.Error("failed to reload certificate",
				zap.String("hostname", files.hostname),
				zap.Error(err),
			)
		}
	}
}

// TLSConfig returns a tls.Config that uses this certificate manager.
func (m *CertificateManager) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
	}
}

// TLSConfigWithClientAuth returns a tls.Config with client certificate authentication.
func (m *CertificateManager) TLSConfigWithClientAuth(clientCAs *x509.CertPool, authType tls.ClientAuthType) *tls.Config {
	config := m.TLSConfig()
	config.ClientCAs = clientCAs
	config.ClientAuth = authType
	return config
}

// LoadClientCAs loads client CA certificates from a file.
func LoadClientCAs(caFile string) (*x509.CertPool, error) {
	// G304: caFile comes from trusted configuration (TLS settings)
	caCert, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return caPool, nil
}

// Close stops the certificate manager and releases resources.
func (m *CertificateManager) Close() error {
	close(m.stopCh)
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}

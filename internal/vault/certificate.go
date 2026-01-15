package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CertificateManager manages TLS certificates from Vault.
type CertificateManager struct {
	client          *Client
	cache           map[string]*CertificateEntry
	mu              sync.RWMutex
	refreshInterval time.Duration
	logger          *zap.Logger
	stopCh          chan struct{}
	stopped         bool
}

// CertificateEntry represents a cached certificate.
type CertificateEntry struct {
	Certificate *tls.Certificate
	ExpiresAt   time.Time
	Path        string
}

// NewCertificateManager creates a new CertificateManager.
func NewCertificateManager(client *Client, refreshInterval time.Duration, logger *zap.Logger) *CertificateManager {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &CertificateManager{
		client:          client,
		cache:           make(map[string]*CertificateEntry),
		refreshInterval: refreshInterval,
		logger:          logger,
		stopCh:          make(chan struct{}),
	}
}

// GetCertificate retrieves a certificate from Vault.
func (m *CertificateManager) GetCertificate(ctx context.Context, path string) (*tls.Certificate, error) {
	m.mu.RLock()
	entry, exists := m.cache[path]
	m.mu.RUnlock()

	if exists && time.Now().Before(entry.ExpiresAt) {
		m.logger.Debug("Certificate retrieved from cache", zap.String("path", path))
		return entry.Certificate, nil
	}

	return m.fetchAndCacheCertificate(ctx, path)
}

// fetchAndCacheCertificate fetches a certificate from Vault and caches it.
func (m *CertificateManager) fetchAndCacheCertificate(ctx context.Context, path string) (*tls.Certificate, error) {
	m.logger.Debug("Fetching certificate from Vault", zap.String("path", path))

	secret, err := m.client.ReadSecret(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate from Vault: %w", err)
	}

	cert, err := m.parseCertificateFromSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate expiry based on certificate NotAfter
	var expiresAt time.Time
	if cert.Leaf != nil {
		// Refresh before actual expiry
		expiresAt = cert.Leaf.NotAfter.Add(-m.refreshInterval)
	} else {
		// Default to refresh interval
		expiresAt = time.Now().Add(m.refreshInterval)
	}

	m.mu.Lock()
	m.cache[path] = &CertificateEntry{
		Certificate: cert,
		ExpiresAt:   expiresAt,
		Path:        path,
	}
	m.mu.Unlock()

	m.logger.Info("Certificate cached",
		zap.String("path", path),
		zap.Time("expiresAt", expiresAt),
	)

	return cert, nil
}

// parseCertificateFromSecret parses a TLS certificate from a Vault secret.
func (m *CertificateManager) parseCertificateFromSecret(secret *Secret) (*tls.Certificate, error) {
	if secret == nil || secret.Data == nil {
		return nil, ErrCertificateInvalid
	}

	// Try common key names for certificate
	certPEM, certOK := m.getSecretValue(secret, "certificate", "cert", "tls.crt", "crt")
	keyPEM, keyOK := m.getSecretValue(secret, "private_key", "key", "tls.key", "private-key")

	if !certOK || !keyOK {
		return nil, fmt.Errorf("%w: missing certificate or key data", ErrCertificateInvalid)
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 key pair: %w", err)
	}

	// Parse the leaf certificate for expiry information
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
		}
	}

	return &cert, nil
}

// getSecretValue tries to get a value from the secret using multiple possible keys.
func (m *CertificateManager) getSecretValue(secret *Secret, keys ...string) (string, bool) {
	for _, key := range keys {
		if v, ok := secret.Data[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// WatchCertificate starts watching a certificate for changes.
func (m *CertificateManager) WatchCertificate(ctx context.Context, path string) error {
	m.logger.Info("Starting certificate watch", zap.String("path", path))

	go func() {
		ticker := time.NewTicker(m.refreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.mu.RLock()
				entry, exists := m.cache[path]
				m.mu.RUnlock()

				// Refresh if entry doesn't exist or is about to expire
				if !exists || time.Now().After(entry.ExpiresAt.Add(-m.refreshInterval/2)) {
					if _, err := m.fetchAndCacheCertificate(ctx, path); err != nil {
						m.logger.Error("Failed to refresh certificate",
							zap.String("path", path),
							zap.Error(err),
						)
					}
				}
			}
		}
	}()

	return nil
}

// TLSConfig creates a TLS configuration using certificates from the specified paths.
func (m *CertificateManager) TLSConfig(ctx context.Context, paths []string) (*tls.Config, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no certificate paths provided")
	}

	// Fetch all certificates
	certs := make([]tls.Certificate, 0, len(paths))
	for _, path := range paths {
		cert, err := m.GetCertificate(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate from %s: %w", path, err)
		}
		certs = append(certs, *cert)
	}

	return &tls.Config{
		Certificates: certs,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// TLSConfigWithCA creates a TLS configuration with CA certificate.
func (m *CertificateManager) TLSConfigWithCA(
	ctx context.Context,
	certPaths []string,
	caPath string,
) (*tls.Config, error) {
	tlsConfig, err := m.TLSConfig(ctx, certPaths)
	if err != nil {
		return nil, err
	}

	// Fetch CA certificate
	caSecret, err := m.client.ReadSecret(ctx, caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caPEM, ok := m.getSecretValue(caSecret, "certificate", "ca", "ca.crt", "ca_chain")
	if !ok {
		return nil, fmt.Errorf("CA certificate not found in secret")
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig.RootCAs = caCertPool
	return tlsConfig, nil
}

// CertificateGetter is a function that returns a certificate for TLS.
type CertificateGetter func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// ClientCertificateGetter is a function that returns a client certificate for TLS.
type ClientCertificateGetter func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

// GetCertificateFunc returns a function suitable for tls.Config.GetCertificate.
func (m *CertificateManager) GetCertificateFunc(
	ctx context.Context,
	path string,
) CertificateGetter {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return m.GetCertificate(ctx, path)
	}
}

// GetClientCertificate returns a function suitable for tls.Config.GetClientCertificate.
func (m *CertificateManager) GetClientCertificate(
	ctx context.Context,
	path string,
) ClientCertificateGetter {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return m.GetCertificate(ctx, path)
	}
}

// InvalidateCertificate removes a certificate from the cache.
func (m *CertificateManager) InvalidateCertificate(path string) {
	m.mu.Lock()
	delete(m.cache, path)
	m.mu.Unlock()
	m.logger.Debug("Certificate invalidated", zap.String("path", path))
}

// ClearCache clears all cached certificates.
func (m *CertificateManager) ClearCache() {
	m.mu.Lock()
	m.cache = make(map[string]*CertificateEntry)
	m.mu.Unlock()
	m.logger.Debug("Certificate cache cleared")
}

// Close stops the certificate manager.
func (m *CertificateManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return nil
	}

	m.stopped = true
	close(m.stopCh)
	m.cache = make(map[string]*CertificateEntry)
	m.logger.Info("Certificate manager closed")

	return nil
}

// ParseCertificatePEM parses a PEM-encoded certificate.
func ParseCertificatePEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

// ParsePrivateKeyPEM parses a PEM-encoded private key.
func ParsePrivateKeyPEM(keyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

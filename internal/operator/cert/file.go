// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// FileProviderConfig contains configuration for the file-based certificate
// provider. The certificate and key are pre-provisioned externally (mounted
// Kubernetes Secret, cert-manager, helm-generated Secret) and reloaded from
// disk when they change or approach expiry, matching the rotation behavior
// of controller-runtime's certwatcher.
type FileProviderConfig struct {
	// CertFile is the path to the PEM-encoded serving certificate
	// (leaf first, optionally followed by intermediates).
	CertFile string

	// KeyFile is the path to the PEM-encoded private key.
	KeyFile string

	// CAFile is the path to the PEM-encoded CA bundle. Optional: when
	// empty, the CA bundle is derived from the extra certificate blocks
	// in CertFile (if any).
	CAFile string

	// RotateBefore is the duration before expiry at which cached
	// certificates are considered stale and re-read from disk.
	RotateBefore time.Duration
}

// fileProvider implements Manager by serving certificates from files.
type fileProvider struct {
	config *FileProviderConfig
	logger observability.Logger

	mu     sync.RWMutex
	cached *Certificate
	// certModTime/keyModTime track the source file modification times of
	// the cached certificate for change detection (external rotation).
	certModTime time.Time
	keyModTime  time.Time
	closed      atomic.Bool
}

// NewFileProvider creates a certificate manager that loads certificates
// from the configured files. The initial load is performed eagerly so
// misconfiguration fails fast at startup.
func NewFileProvider(config *FileProviderConfig) (Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("file provider configuration is required")
	}
	if config.CertFile == "" || config.KeyFile == "" {
		return nil, fmt.Errorf("certFile and keyFile are required for the file certificate provider")
	}
	if config.RotateBefore == 0 {
		config.RotateBefore = DefaultRotateBefore
	}

	p := &fileProvider{
		config: config,
		logger: observability.GetGlobalLogger().With(
			observability.String("component", "cert-manager"),
			observability.String("provider", providerFile),
		),
	}

	cert, err := p.load()
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate files: %w", err)
	}

	p.logger.Info("file certificate provider initialized",
		observability.String("cert_file", config.CertFile),
		observability.String("key_file", config.KeyFile),
		observability.String("ca_file", config.CAFile),
		observability.String("common_name", cert.Certificate.Subject.CommonName),
		observability.Time("expiration", cert.Expiration),
	)

	return p, nil
}

// GetCertificate returns the certificate loaded from the configured files.
// The CommonName/DNSNames in the request are informational only — the files
// are authoritative. The cached certificate is transparently re-read when
// the source files change or the certificate approaches expiry.
func (p *fileProvider) GetCertificate(ctx context.Context, _ *CertificateRequest) (*Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}
	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	p.mu.RLock()
	cached := p.cached
	fresh := cached != nil && cached.IsValid() &&
		!cached.IsExpiringSoon(p.config.RotateBefore) && !p.filesChangedLocked()
	p.mu.RUnlock()

	if fresh {
		return cached, nil
	}

	return p.reload()
}

// GetCA returns the CA certificate pool.
func (p *fileProvider) GetCA(ctx context.Context) (*x509.CertPool, error) {
	caPEM, err := p.GetCAPEM(ctx)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to parse CA bundle from %s", p.caSource())
	}
	return pool, nil
}

// GetCAPEM returns the PEM-encoded CA bundle from CAFile, or the
// non-leaf certificate blocks of CertFile when no CAFile is configured.
func (p *fileProvider) GetCAPEM(_ context.Context) ([]byte, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	if p.config.CAFile != "" {
		caPEM, err := os.ReadFile(p.config.CAFile)
		if err != nil {
			GetCertMetrics().errorsTotal.WithLabelValues(providerFile, "load").Inc()
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		if len(caPEM) == 0 {
			return nil, fmt.Errorf("CA file %s is empty", p.config.CAFile)
		}
		return caPEM, nil
	}

	p.mu.RLock()
	cached := p.cached
	p.mu.RUnlock()

	if cached == nil || len(cached.CAChainPEM) == 0 {
		return nil, fmt.Errorf("no CA bundle available: caFile not configured and %s has no chain",
			p.config.CertFile)
	}
	return cached.CAChainPEM, nil
}

// RotateCertificate forces a re-read of the certificate files. External
// tooling (cert-manager, helm upgrade) performs the actual rotation on disk.
func (p *fileProvider) RotateCertificate(ctx context.Context, _ *CertificateRequest) (*Certificate, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}
	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	GetCertMetrics().rotationsTotal.WithLabelValues(providerFile).Inc()
	return p.reload()
}

// Close closes the provider.
func (p *fileProvider) Close() error {
	p.closed.Store(true)

	p.mu.Lock()
	p.cached = nil
	p.mu.Unlock()

	return nil
}

// caSource describes where the CA bundle comes from (for error messages).
func (p *fileProvider) caSource() string {
	if p.config.CAFile != "" {
		return p.config.CAFile
	}
	return p.config.CertFile
}

// filesChangedLocked reports whether the source files were modified since
// the cached certificate was loaded. Stat errors count as "changed" so the
// subsequent reload surfaces the underlying problem. Must be called with
// p.mu held (read or write).
func (p *fileProvider) filesChangedLocked() bool {
	certInfo, err := os.Stat(p.config.CertFile)
	if err != nil {
		return true
	}
	keyInfo, err := os.Stat(p.config.KeyFile)
	if err != nil {
		return true
	}
	return !certInfo.ModTime().Equal(p.certModTime) || !keyInfo.ModTime().Equal(p.keyModTime)
}

// reload re-reads the certificate files and swaps the cache.
func (p *fileProvider) reload() (*Certificate, error) {
	cert, err := p.load()
	if err != nil {
		return nil, fmt.Errorf("failed to reload certificate files: %w", err)
	}
	return cert, nil
}

// load reads, validates, and caches the certificate/key pair from disk.
func (p *fileProvider) load() (*Certificate, error) {
	certPEM, keyPEM, certMod, keyMod, err := p.readFiles()
	if err != nil {
		GetCertMetrics().errorsTotal.WithLabelValues(providerFile, "load").Inc()
		return nil, err
	}

	cert, err := p.buildCertificate(certPEM, keyPEM)
	if err != nil {
		GetCertMetrics().errorsTotal.WithLabelValues(providerFile, "load").Inc()
		return nil, err
	}

	p.mu.Lock()
	p.cached = cert
	p.certModTime = certMod
	p.keyModTime = keyMod
	p.mu.Unlock()

	cm := GetCertMetrics()
	cm.issuedTotal.WithLabelValues(providerFile).Inc()
	cm.expirySeconds.WithLabelValues(
		cert.Certificate.Subject.CommonName,
	).Set(time.Until(cert.Expiration).Seconds())

	p.logger.Info("certificate loaded from files",
		observability.String("common_name", cert.Certificate.Subject.CommonName),
		observability.Time("expiration", cert.Expiration),
	)

	return cert, nil
}

// readFiles reads the certificate and key files along with their
// modification times (captured before the reads to avoid a rotation
// window where content and mtime disagree).
func (p *fileProvider) readFiles() (certPEM, keyPEM []byte, certMod, keyMod time.Time, err error) {
	certInfo, err := os.Stat(p.config.CertFile)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("failed to stat certificate file: %w", err)
	}
	keyInfo, err := os.Stat(p.config.KeyFile)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("failed to stat key file: %w", err)
	}

	certPEM, err = os.ReadFile(p.config.CertFile)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("failed to read certificate file: %w", err)
	}
	keyPEM, err = os.ReadFile(p.config.KeyFile)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("failed to read key file: %w", err)
	}

	return certPEM, keyPEM, certInfo.ModTime(), keyInfo.ModTime(), nil
}

// buildCertificate validates the PEM pair and assembles the Certificate,
// including the CA chain (CAFile preferred, CertFile extra blocks as
// fallback).
func (p *fileProvider) buildCertificate(certPEM, keyPEM []byte) (*Certificate, error) {
	// tls.X509KeyPair validates that the key matches the certificate.
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate/key pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	caChainPEM := p.loadCAChain(certPEM)

	return &Certificate{
		Certificate:    leaf,
		PrivateKey:     tlsCert.PrivateKey,
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		CAChainPEM:     caChainPEM,
		SerialNumber:   leaf.SerialNumber.String(),
		Expiration:     leaf.NotAfter,
	}, nil
}

// loadCAChain returns the CA chain PEM: the CAFile content when
// configured (missing/unreadable file logged, not fatal — GetCAPEM
// surfaces the error to callers that require a CA), otherwise the
// certificate blocks following the leaf in certPEM.
func (p *fileProvider) loadCAChain(certPEM []byte) []byte {
	if p.config.CAFile != "" {
		caPEM, err := os.ReadFile(p.config.CAFile)
		if err != nil {
			p.logger.Warn("failed to read CA file; CA chain unavailable",
				observability.String("ca_file", p.config.CAFile),
				observability.Error(err),
			)
			return nil
		}
		return caPEM
	}
	return extraCertBlocks(certPEM)
}

// extraCertBlocks returns all CERTIFICATE PEM blocks after the first
// (the leaf), preserving their PEM encoding. Returns nil when the input
// contains a single certificate.
func extraCertBlocks(certPEM []byte) []byte {
	var out []byte
	rest := certPEM
	first := true
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != pemTypeCertificate {
			continue
		}
		if first {
			first = false
			continue
		}
		out = append(out, pem.EncodeToMemory(block)...)
	}
	return out
}

// Ensure fileProvider implements Manager.
var _ Manager = (*fileProvider)(nil)

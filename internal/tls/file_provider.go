package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// FileProvider loads certificates from files and supports hot-reload.
type FileProvider struct {
	config *CertificateConfig
	client *ClientValidationConfig
	logger observability.Logger

	certificate atomic.Pointer[tls.Certificate]
	clientCA    atomic.Pointer[x509.CertPool]

	watcher   *fsnotify.Watcher
	eventCh   chan CertificateEvent
	stopCh    chan struct{}
	stoppedCh chan struct{}

	mu      sync.RWMutex
	closed  bool
	started bool

	// Debounce settings
	debounceDelay time.Duration
}

// FileProviderOption is a functional option for configuring FileProvider.
type FileProviderOption func(*FileProvider)

// WithFileProviderLogger sets the logger for the file provider.
func WithFileProviderLogger(logger observability.Logger) FileProviderOption {
	return func(p *FileProvider) {
		p.logger = logger
	}
}

// WithDebounceDelay sets the debounce delay for file change events.
func WithDebounceDelay(delay time.Duration) FileProviderOption {
	return func(p *FileProvider) {
		p.debounceDelay = delay
	}
}

// NewFileProvider creates a new file-based certificate provider.
func NewFileProvider(
	config *CertificateConfig,
	clientConfig *ClientValidationConfig,
	opts ...FileProviderOption,
) (*FileProvider, error) {
	if config == nil {
		return nil, NewConfigurationError("config", "certificate configuration is required")
	}

	p := &FileProvider{
		config:        config,
		client:        clientConfig,
		logger:        observability.NopLogger(),
		eventCh:       make(chan CertificateEvent, 10),
		stopCh:        make(chan struct{}),
		stoppedCh:     make(chan struct{}),
		debounceDelay: 100 * time.Millisecond,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Load initial certificate
	if err := p.loadCertificate(); err != nil {
		return nil, err
	}

	// Load client CA if configured
	if clientConfig != nil && clientConfig.Enabled {
		if err := p.loadClientCA(); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// Start begins watching for certificate file changes.
func (p *FileProvider) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}
	p.started = true
	p.mu.Unlock()

	// Only set up file watching if reload interval is configured
	if p.config.ReloadInterval <= 0 {
		p.logger.Debug("certificate hot-reload disabled (no reload interval configured)")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return WrapError(err, "failed to create file watcher")
	}
	p.watcher = watcher

	// Watch certificate files
	if p.config.CertFile != "" {
		dir := filepath.Dir(p.config.CertFile)
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return WrapError(err, "failed to watch certificate directory")
		}
		p.logger.Info("watching certificate file",
			observability.String("path", p.config.CertFile),
		)
	}

	if p.config.KeyFile != "" && filepath.Dir(p.config.KeyFile) != filepath.Dir(p.config.CertFile) {
		dir := filepath.Dir(p.config.KeyFile)
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return WrapError(err, "failed to watch key directory")
		}
		p.logger.Info("watching key file",
			observability.String("path", p.config.KeyFile),
		)
	}

	// Watch CA file if configured
	if p.client != nil && p.client.CAFile != "" {
		dir := filepath.Dir(p.client.CAFile)
		if err := watcher.Add(dir); err != nil {
			p.logger.Warn("failed to watch CA directory",
				observability.String("path", dir),
				observability.Error(err),
			)
		}
	}

	go p.watchLoop(ctx)

	// Send initial loaded event
	p.sendEvent(CertificateEvent{
		Type:        CertificateEventLoaded,
		Certificate: p.certificate.Load(),
		Message:     "certificate loaded",
	})

	return nil
}

// GetCertificate returns the current certificate.
func (p *FileProvider) GetCertificate(_ context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrProviderClosed
	}
	p.mu.RUnlock()

	cert := p.certificate.Load()
	if cert == nil {
		return nil, ErrCertificateNotFound
	}

	return cert, nil
}

// GetClientCA returns the client CA certificate pool.
func (p *FileProvider) GetClientCA(_ context.Context) (*x509.CertPool, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, ErrProviderClosed
	}
	p.mu.RUnlock()

	return p.clientCA.Load(), nil
}

// Watch returns a channel that receives certificate events.
func (p *FileProvider) Watch(_ context.Context) <-chan CertificateEvent {
	return p.eventCh
}

// Close stops the file watcher and releases resources.
func (p *FileProvider) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()

	close(p.stopCh)

	if p.started {
		<-p.stoppedCh
	}

	if p.watcher != nil {
		if err := p.watcher.Close(); err != nil {
			return WrapError(err, "failed to close file watcher")
		}
	}

	close(p.eventCh)

	return nil
}

// loadCertificate loads the certificate from files or inline data.
func (p *FileProvider) loadCertificate() error {
	var cert tls.Certificate
	var err error

	source := p.config.GetEffectiveSource()

	switch source {
	case CertificateSourceFile:
		cert, err = tls.LoadX509KeyPair(p.config.CertFile, p.config.KeyFile)
		if err != nil {
			return NewCertificateErrorWithCause(p.config.CertFile, "failed to load certificate", err)
		}

	case CertificateSourceInline:
		cert, err = tls.X509KeyPair([]byte(p.config.CertData), []byte(p.config.KeyData))
		if err != nil {
			return NewCertificateErrorWithCause("", "failed to parse inline certificate", err)
		}

	default:
		return NewConfigurationError("source", "unsupported certificate source: "+string(source))
	}

	// Parse the leaf certificate for logging
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
			p.logger.Info("certificate loaded",
				observability.String("subject", leaf.Subject.CommonName),
				observability.Time("notBefore", leaf.NotBefore),
				observability.Time("notAfter", leaf.NotAfter),
			)
		}
	}

	p.certificate.Store(&cert)
	return nil
}

// loadClientCA loads the client CA certificate pool.
func (p *FileProvider) loadClientCA() error {
	if p.client == nil {
		return nil
	}

	caData, err := p.readCAData()
	if err != nil {
		return err
	}
	if caData == nil {
		return nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return NewCertificateError(p.client.CAFile, "failed to parse CA certificates")
	}

	p.clientCA.Store(pool)
	p.logger.Info("client CA loaded",
		observability.String("path", p.client.CAFile),
	)

	return nil
}

// readCAData reads CA data from file or inline configuration.
func (p *FileProvider) readCAData() ([]byte, error) {
	switch {
	case p.client.CAFile != "":
		caData, err := os.ReadFile(p.client.CAFile) // #nosec G304 -- CA file path from config
		if err != nil {
			return nil, NewCertificateErrorWithCause(p.client.CAFile, "failed to read CA file", err)
		}
		return caData, nil
	case p.client.CAData != "":
		return []byte(p.client.CAData), nil
	default:
		return nil, nil
	}
}

// watchLoop handles file change events.
func (p *FileProvider) watchLoop(ctx context.Context) {
	defer close(p.stoppedCh)

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("certificate watcher stopped due to context cancellation")
			return

		case <-p.stopCh:
			p.logger.Info("certificate watcher stopped")
			return

		case event, ok := <-p.watcher.Events:
			if !ok {
				return
			}
			debounceTimer, debounceCh = p.handleFileEvent(event, debounceTimer, debounceCh)

		case <-debounceCh:
			debounceCh = nil
			p.reload()

		case err, ok := <-p.watcher.Errors:
			if !ok {
				return
			}
			p.logger.Error("file watcher error", observability.Error(err))
			p.sendEvent(CertificateEvent{
				Type:    CertificateEventError,
				Error:   err,
				Message: "file watcher error",
			})
		}
	}
}

// handleFileEvent processes a file system event.
func (p *FileProvider) handleFileEvent(
	event fsnotify.Event,
	debounceTimer *time.Timer,
	debounceCh <-chan time.Time,
) (timer *time.Timer, ch <-chan time.Time) {
	// Check if this is a relevant file
	cleanPath := filepath.Clean(event.Name)
	isRelevant := p.isRelevantFile(cleanPath)

	if !isRelevant {
		return debounceTimer, debounceCh
	}

	// Check if this is a write or create event
	if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
		return debounceTimer, debounceCh
	}

	p.logger.Debug("certificate file changed",
		observability.String("path", event.Name),
		observability.String("op", event.Op.String()),
	)

	// Reset debounce timer
	if debounceTimer != nil {
		debounceTimer.Stop()
	}
	debounceTimer = time.NewTimer(p.debounceDelay)
	return debounceTimer, debounceTimer.C
}

// isRelevantFile checks if the given path is a file we're watching.
func (p *FileProvider) isRelevantFile(cleanPath string) bool {
	if p.config.CertFile != "" && cleanPath == filepath.Clean(p.config.CertFile) {
		return true
	}
	if p.config.KeyFile != "" && cleanPath == filepath.Clean(p.config.KeyFile) {
		return true
	}
	if p.client != nil && p.client.CAFile != "" && cleanPath == filepath.Clean(p.client.CAFile) {
		return true
	}
	return false
}

// reload reloads the certificate and CA.
func (p *FileProvider) reload() {
	p.logger.Info("reloading certificates")

	// Reload certificate
	if err := p.loadCertificate(); err != nil {
		p.logger.Error("failed to reload certificate", observability.Error(err))
		p.sendEvent(CertificateEvent{
			Type:    CertificateEventError,
			Error:   err,
			Message: "failed to reload certificate",
		})
		return
	}

	// Reload CA if configured
	if p.client != nil && p.client.Enabled {
		if err := p.loadClientCA(); err != nil {
			p.logger.Error("failed to reload client CA", observability.Error(err))
			p.sendEvent(CertificateEvent{
				Type:    CertificateEventError,
				Error:   err,
				Message: "failed to reload client CA",
			})
			return
		}
	}

	p.sendEvent(CertificateEvent{
		Type:        CertificateEventReloaded,
		Certificate: p.certificate.Load(),
		Message:     "certificate reloaded",
	})

	p.logger.Info("certificates reloaded successfully")
}

// sendEvent sends an event to the event channel.
func (p *FileProvider) sendEvent(event CertificateEvent) {
	select {
	case p.eventCh <- event:
	default:
		p.logger.Warn("certificate event channel full, dropping event",
			observability.String("type", event.Type.String()),
		)
	}
}

// Ensure FileProvider implements CertificateProvider.
var _ CertificateProvider = (*FileProvider)(nil)

// LoadCertificateFromFile loads a certificate from PEM files.
func LoadCertificateFromFile(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, NewCertificateErrorWithCause(certFile, "failed to load certificate", err)
	}

	// Parse the leaf certificate
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
		}
	}

	return &cert, nil
}

// LoadCertificateFromPEM loads a certificate from PEM data.
func LoadCertificateFromPEM(certPEM, keyPEM []byte) (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, NewCertificateErrorWithCause("", "failed to parse certificate", err)
	}

	// Parse the leaf certificate
	if len(cert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err == nil {
			cert.Leaf = leaf
		}
	}

	return &cert, nil
}

// LoadCAFromFile loads a CA certificate pool from a PEM file.
func LoadCAFromFile(caFile string) (*x509.CertPool, error) {
	caData, err := os.ReadFile(caFile) // #nosec G304 -- CA file path from trusted config
	if err != nil {
		return nil, NewCertificateErrorWithCause(caFile, "failed to read CA file", err)
	}

	return LoadCAFromPEM(caData)
}

// LoadCAFromPEM loads a CA certificate pool from PEM data.
func LoadCAFromPEM(caPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, NewCertificateError("", "failed to parse CA certificates")
	}
	return pool, nil
}

// ParsePEMCertificates parses PEM-encoded certificates.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, NewCertificateErrorWithCause("", "failed to parse certificate", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, NewCertificateError("", "no certificates found in PEM data")
	}

	return certs, nil
}

// DecryptPEMBlock decrypts an encrypted PEM block.
// This function is kept for backward compatibility with legacy systems.
//
// Deprecated: Legacy PEM encryption (RFC 1423) is insecure. Use modern key encryption instead.
func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
	//nolint:staticcheck // SA1019: kept for backward compatibility with legacy systems
	if !x509.IsEncryptedPEMBlock(block) {
		return block.Bytes, nil
	}

	//nolint:staticcheck // SA1019: kept for backward compatibility with legacy systems
	der, err := x509.DecryptPEMBlock(block, password)
	if err != nil {
		return nil, NewCertificateErrorWithCause("", "failed to decrypt PEM block", err)
	}

	return der, nil
}

// LoadEncryptedKeyFromFile loads an encrypted private key from a file.
// This function is kept for backward compatibility with legacy systems.
//
// Deprecated: Legacy PEM encryption (RFC 1423) is insecure. Use modern key encryption instead.
func LoadEncryptedKeyFromFile(keyFile string, password []byte) ([]byte, error) {
	keyData, err := os.ReadFile(keyFile) // #nosec G304 -- key file path from trusted config
	if err != nil {
		return nil, NewCertificateErrorWithCause(keyFile, "failed to read key file", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, NewCertificateError(keyFile, "failed to decode PEM block")
	}

	//nolint:staticcheck // SA1019: kept for backward compatibility with legacy systems
	if x509.IsEncryptedPEMBlock(block) {
		decrypted, err := DecryptPEMBlock(block, password)
		if err != nil {
			return nil, err
		}

		// Re-encode as unencrypted PEM
		return pem.EncodeToMemory(&pem.Block{
			Type:  block.Type,
			Bytes: decrypted,
		}), nil
	}

	return keyData, nil
}

// ValidateCertificateKeyPair validates that a certificate and key match.
func ValidateCertificateKeyPair(certPEM, keyPEM []byte) error {
	_, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		if errors.Is(err, x509.IncorrectPasswordError) {
			return NewCertificateErrorWithCause("", "incorrect password for encrypted key", err)
		}
		return NewCertificateErrorWithCause("", "certificate and key do not match", ErrCertificateKeyMismatch)
	}
	return nil
}

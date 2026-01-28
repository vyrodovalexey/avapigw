package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"

	internaltls "github.com/vyrodovalexey/avapigw/internal/tls"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
)

// VaultProvider implements tls.CertificateProvider using Vault PKI.
type VaultProvider struct {
	client  Client
	config  *VaultProviderConfig
	logger  observability.Logger
	metrics *Metrics

	// Current certificate
	cert     atomic.Pointer[tls.Certificate]
	certInfo atomic.Pointer[internaltls.CertificateInfo]

	// CA pool
	caPool atomic.Pointer[x509.CertPool]

	// Event channel
	eventCh chan internaltls.CertificateEvent

	// Lifecycle
	mu        sync.RWMutex
	closed    bool
	started   bool
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

// VaultProviderConfig configures the Vault certificate provider.
type VaultProviderConfig struct {
	// PKIMount is the PKI secrets engine mount path.
	PKIMount string `yaml:"pkiMount" json:"pkiMount"`

	// Role is the PKI role name.
	Role string `yaml:"role" json:"role"`

	// CommonName is the certificate common name.
	CommonName string `yaml:"commonName" json:"commonName"`

	// AltNames are the subject alternative names.
	AltNames []string `yaml:"altNames,omitempty" json:"altNames,omitempty"`

	// IPSANs are the IP subject alternative names.
	IPSANs []string `yaml:"ipSans,omitempty" json:"ipSans,omitempty"`

	// TTL is the certificate TTL.
	TTL time.Duration `yaml:"ttl,omitempty" json:"ttl,omitempty"`

	// RenewBefore is the duration before expiry to renew.
	RenewBefore time.Duration `yaml:"renewBefore,omitempty" json:"renewBefore,omitempty"`

	// CAMount is the CA mount path (defaults to PKIMount).
	CAMount string `yaml:"caMount,omitempty" json:"caMount,omitempty"`
}

// VaultProviderOption is a functional option for configuring VaultProvider.
type VaultProviderOption func(*VaultProvider)

// WithVaultProviderLogger sets the logger for the provider.
func WithVaultProviderLogger(logger observability.Logger) VaultProviderOption {
	return func(p *VaultProvider) {
		p.logger = logger
	}
}

// WithVaultProviderMetrics sets the metrics for the provider.
func WithVaultProviderMetrics(metrics *Metrics) VaultProviderOption {
	return func(p *VaultProvider) {
		p.metrics = metrics
	}
}

// NewVaultProvider creates a new Vault-based certificate provider.
func NewVaultProvider(
	client Client,
	config *VaultProviderConfig,
	opts ...VaultProviderOption,
) (*VaultProvider, error) {
	if client == nil {
		return nil, NewConfigurationError("client", "vault client is required")
	}

	if !client.IsEnabled() {
		return nil, ErrVaultDisabled
	}

	if config == nil {
		return nil, NewConfigurationError("config", "configuration is required")
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	p := &VaultProvider{
		client:    client,
		config:    config,
		logger:    observability.NopLogger(),
		eventCh:   make(chan internaltls.CertificateEvent, 10),
		stopCh:    make(chan struct{}),
		stoppedCh: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.metrics == nil {
		p.metrics = NewMetrics("gateway")
	}

	return p, nil
}

// Start initializes the provider and begins certificate management.
func (p *VaultProvider) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return nil
	}
	p.started = true
	p.mu.Unlock()

	// Issue initial certificate
	if err := p.issueCertificate(ctx); err != nil {
		return err
	}

	// Load CA pool
	if err := p.loadCAPool(ctx); err != nil {
		p.logger.Warn("failed to load CA pool", observability.Error(err))
	}

	// Start renewal goroutine
	go p.renewalLoop(ctx)

	// Send initial loaded event
	p.sendEvent(internaltls.CertificateEvent{
		Type:        internaltls.CertificateEventLoaded,
		Certificate: p.cert.Load(),
		Message:     "certificate loaded from vault",
	})

	return nil
}

// GetCertificate returns the current certificate.
func (p *VaultProvider) GetCertificate(_ context.Context, _ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, internaltls.ErrProviderClosed
	}
	p.mu.RUnlock()

	cert := p.cert.Load()
	if cert == nil {
		return nil, internaltls.ErrCertificateNotFound
	}

	return cert, nil
}

// GetClientCA returns the CA certificate pool.
func (p *VaultProvider) GetClientCA(_ context.Context) (*x509.CertPool, error) {
	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return nil, internaltls.ErrProviderClosed
	}
	p.mu.RUnlock()

	return p.caPool.Load(), nil
}

// Watch returns a channel that receives certificate events.
func (p *VaultProvider) Watch(_ context.Context) <-chan internaltls.CertificateEvent {
	return p.eventCh
}

// Close stops the provider and releases resources.
func (p *VaultProvider) Close() error {
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

	close(p.eventCh)

	p.logger.Info("vault provider closed")
	return nil
}

// issueCertificate issues a new certificate from Vault.
func (p *VaultProvider) issueCertificate(ctx context.Context) error {
	// Check for context cancellation before starting the operation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Context is still valid, proceed with certificate issuance
	}

	opts := &PKIIssueOptions{
		Mount:      p.config.PKIMount,
		Role:       p.config.Role,
		CommonName: p.config.CommonName,
		AltNames:   p.config.AltNames,
		IPSANs:     p.config.IPSANs,
		TTL:        p.config.TTL,
		Format:     "pem",
	}

	cert, err := p.client.PKI().IssueCertificate(ctx, opts)
	if err != nil {
		return err
	}

	// Create tls.Certificate
	tlsCert, err := tls.X509KeyPair([]byte(cert.CertificatePEM), []byte(cert.PrivateKeyPEM))
	if err != nil {
		return NewVaultErrorWithCause("pki_issue", "", "failed to create TLS certificate", err)
	}

	// Parse the leaf certificate
	if len(tlsCert.Certificate) > 0 {
		leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err == nil {
			tlsCert.Leaf = leaf

			// Store certificate info
			info := internaltls.ExtractCertificateInfo(leaf)
			p.certInfo.Store(info)
		}
	}

	p.cert.Store(&tlsCert)

	p.logger.Info("certificate issued from vault",
		observability.String("common_name", p.config.CommonName),
		observability.String("serial", cert.SerialNumber),
		observability.Time("expiration", cert.Expiration),
	)

	return nil
}

// loadCAPool loads the CA certificate pool from Vault.
func (p *VaultProvider) loadCAPool(ctx context.Context) error {
	// Check for context cancellation before starting the operation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Context is still valid, proceed with CA pool loading
	}

	mount := p.config.CAMount
	if mount == "" {
		mount = p.config.PKIMount
	}

	pool, err := p.client.PKI().GetCA(ctx, mount)
	if err != nil {
		return err
	}

	p.caPool.Store(pool)
	p.logger.Info("CA pool loaded from vault",
		observability.String("mount", mount),
	)

	return nil
}

// renewalLoop handles automatic certificate renewal.
func (p *VaultProvider) renewalLoop(ctx context.Context) {
	defer close(p.stoppedCh)

	renewBefore := p.config.RenewBefore
	if renewBefore <= 0 {
		renewBefore = 10 * time.Minute
	}

	// Calculate initial renewal time
	renewAt := p.calculateRenewalTime(renewBefore)
	timer := time.NewTimer(time.Until(renewAt))
	defer timer.Stop()

	p.logger.Info("started certificate renewal loop",
		observability.Time("next_renewal", renewAt),
	)

	// Exponential backoff parameters for renewal failures
	const (
		renewalInitialBackoff = 5 * time.Second
		renewalMaxBackoff     = 5 * time.Minute
		renewalJitterFactor   = 0.25
	)
	var retryAttempt int

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("certificate renewal stopped due to context cancellation")
			return
		case <-p.stopCh:
			p.logger.Info("certificate renewal stopped")
			return
		case <-timer.C:
			p.logger.Info("renewing certificate")

			if err := p.issueCertificate(ctx); err != nil {
				p.logger.Error("failed to renew certificate",
					observability.Error(err),
					observability.Int("retry_attempt", retryAttempt),
				)
				p.sendEvent(internaltls.CertificateEvent{
					Type:    internaltls.CertificateEventError,
					Error:   err,
					Message: "failed to renew certificate",
				})

				// Retry with exponential backoff
				backoff := retry.CalculateBackoff(
					retryAttempt, renewalInitialBackoff, renewalMaxBackoff, renewalJitterFactor,
				)
				retryAttempt++
				p.logger.Info("scheduling certificate renewal retry",
					observability.Int("retry_attempt", retryAttempt),
					observability.Duration("backoff", backoff),
				)
				timer.Reset(backoff)
				continue
			}

			// Reset retry counter on success
			retryAttempt = 0

			p.sendEvent(internaltls.CertificateEvent{
				Type:        internaltls.CertificateEventReloaded,
				Certificate: p.cert.Load(),
				Message:     "certificate renewed from vault",
			})

			// Calculate next renewal time
			renewAt = p.calculateRenewalTime(renewBefore)
			timer.Reset(time.Until(renewAt))

			p.logger.Info("certificate renewed",
				observability.Time("next_renewal", renewAt),
			)
		}
	}
}

// calculateRenewalTime calculates when to renew the certificate.
func (p *VaultProvider) calculateRenewalTime(renewBefore time.Duration) time.Time {
	cert := p.cert.Load()
	if cert == nil || cert.Leaf == nil {
		// If no certificate, renew immediately
		return time.Now()
	}

	renewAt := cert.Leaf.NotAfter.Add(-renewBefore)

	// Don't schedule renewal in the past
	if renewAt.Before(time.Now()) {
		return time.Now()
	}

	return renewAt
}

// sendEvent sends an event to the event channel.
func (p *VaultProvider) sendEvent(event internaltls.CertificateEvent) {
	select {
	case p.eventCh <- event:
	default:
		p.logger.Warn("certificate event channel full, dropping event",
			observability.String("type", event.Type.String()),
		)
	}
}

// GetCertificateInfo returns information about the current certificate.
func (p *VaultProvider) GetCertificateInfo() *internaltls.CertificateInfo {
	return p.certInfo.Load()
}

// Validate validates the provider configuration.
func (c *VaultProviderConfig) Validate() error {
	if c == nil {
		return NewConfigurationError("", "configuration is nil")
	}

	if c.PKIMount == "" {
		return NewConfigurationError("pkiMount", "PKI mount is required")
	}

	if c.Role == "" {
		return NewConfigurationError("role", "role is required")
	}

	if c.CommonName == "" {
		return NewConfigurationError("commonName", "common name is required")
	}

	if c.TTL < 0 {
		return NewConfigurationError("ttl", "TTL cannot be negative")
	}

	if c.RenewBefore < 0 {
		return NewConfigurationError("renewBefore", "renewBefore cannot be negative")
	}

	if c.TTL > 0 && c.RenewBefore >= c.TTL {
		return NewConfigurationError("renewBefore", "renewBefore must be less than TTL")
	}

	return nil
}

// Clone creates a deep copy of the configuration.
func (c *VaultProviderConfig) Clone() *VaultProviderConfig {
	if c == nil {
		return nil
	}

	clone := &VaultProviderConfig{
		PKIMount:    c.PKIMount,
		Role:        c.Role,
		CommonName:  c.CommonName,
		TTL:         c.TTL,
		RenewBefore: c.RenewBefore,
		CAMount:     c.CAMount,
	}

	if len(c.AltNames) > 0 {
		clone.AltNames = make([]string, len(c.AltNames))
		copy(clone.AltNames, c.AltNames)
	}

	if len(c.IPSANs) > 0 {
		clone.IPSANs = make([]string, len(c.IPSANs))
		copy(clone.IPSANs, c.IPSANs)
	}

	return clone
}

// Ensure VaultProvider implements CertificateProvider.
var _ internaltls.CertificateProvider = (*VaultProvider)(nil)

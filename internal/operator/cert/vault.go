// Package cert provides certificate management for the operator.
package cert

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/retry"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Default retry configuration constants for Vault authentication.
const (
	// DefaultVaultMaxRetries is the default maximum number of retry attempts.
	DefaultVaultMaxRetries = 3

	// DefaultVaultRetryBaseDelay is the default base delay for exponential backoff.
	DefaultVaultRetryBaseDelay = 1 * time.Second

	// DefaultVaultRetryMaxDelay is the default maximum delay for exponential backoff.
	DefaultVaultRetryMaxDelay = 30 * time.Second
)

// vaultAuthMetrics contains Prometheus metrics for Vault authentication.
type vaultAuthMetrics struct {
	authRetriesTotal *prometheus.CounterVec
}

var (
	vaultAuthMetricsInstance *vaultAuthMetrics
	vaultAuthMetricsOnce     sync.Once
)

// getVaultAuthMetrics returns the singleton instance of Vault authentication metrics.
func getVaultAuthMetrics() *vaultAuthMetrics {
	vaultAuthMetricsOnce.Do(func() {
		vaultAuthMetricsInstance = &vaultAuthMetrics{
			authRetriesTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Namespace: "avapigw_operator",
					Subsystem: "vault",
					Name:      "auth_retries_total",
					Help:      "Total number of Vault authentication retry attempts",
				},
				[]string{"result"},
			),
		}
	})
	return vaultAuthMetricsInstance
}

// VaultProviderConfig contains configuration for the Vault certificate provider.
type VaultProviderConfig struct {
	// Address is the Vault server address.
	Address string

	// PKIMount is the Vault PKI mount path.
	PKIMount string

	// Role is the Vault PKI role name.
	Role string

	// TTL is the default certificate TTL.
	TTL time.Duration

	// RotateBefore is the duration before expiry to rotate certificates.
	RotateBefore time.Duration

	// MaxRetries is the maximum number of retry attempts for Vault authentication.
	// Default is 3.
	MaxRetries int

	// RetryBaseDelay is the base delay for exponential backoff.
	// Default is 1 second.
	RetryBaseDelay time.Duration

	// RetryMaxDelay is the maximum delay for exponential backoff.
	// Default is 30 seconds.
	RetryMaxDelay time.Duration
}

// vaultProvider implements Manager using Vault PKI.
type vaultProvider struct {
	config      *VaultProviderConfig
	vaultClient vault.Client
	logger      observability.Logger
	metrics     *vaultAuthMetrics

	mu     sync.RWMutex
	certs  map[string]*Certificate
	closed atomic.Bool
}

// NewVaultProvider creates a new Vault certificate provider.
func NewVaultProvider(ctx context.Context, config *VaultProviderConfig) (Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}

	if config.PKIMount == "" {
		config.PKIMount = "pki"
	}

	if config.Role == "" {
		return nil, fmt.Errorf("vault PKI role is required")
	}

	if config.TTL == 0 {
		config.TTL = 24 * time.Hour
	}

	if config.RotateBefore == 0 {
		config.RotateBefore = 1 * time.Hour
	}

	// Apply retry configuration defaults
	if config.MaxRetries <= 0 {
		config.MaxRetries = DefaultVaultMaxRetries
	}

	if config.RetryBaseDelay <= 0 {
		config.RetryBaseDelay = DefaultVaultRetryBaseDelay
	}

	if config.RetryMaxDelay <= 0 {
		config.RetryMaxDelay = DefaultVaultRetryMaxDelay
	}

	logger := observability.GetGlobalLogger().With(observability.String("component", "vault-cert-manager"))
	metrics := getVaultAuthMetrics()

	// Create Vault client
	vaultClient, err := vault.New(&vault.Config{
		Enabled: true,
		Address: config.Address,
		// Auth will be configured via environment or Kubernetes service account
		AuthMethod: vault.AuthMethodKubernetes,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// Authenticate with Vault using retry with exponential backoff
	if err := authenticateWithRetry(ctx, vaultClient, config, logger, metrics); err != nil {
		return nil, err
	}

	p := &vaultProvider{
		config:      config,
		vaultClient: vaultClient,
		logger:      logger,
		metrics:     metrics,
		certs:       make(map[string]*Certificate),
	}

	p.logger.Info("vault certificate provider initialized",
		observability.String("address", config.Address),
		observability.String("pki_mount", config.PKIMount),
		observability.String("role", config.Role),
	)

	return p, nil
}

// authenticateWithRetry performs Vault authentication with exponential backoff retry.
func authenticateWithRetry(
	ctx context.Context,
	vaultClient vault.Client,
	config *VaultProviderConfig,
	logger observability.Logger,
	metrics *vaultAuthMetrics,
) error {
	retryCfg := &retry.Config{
		MaxRetries:     config.MaxRetries,
		InitialBackoff: config.RetryBaseDelay,
		MaxBackoff:     config.RetryMaxDelay,
		JitterFactor:   retry.DefaultJitterFactor,
	}

	var authErrors []error
	attemptCount := 0

	retryOpts := &retry.Options{
		OnRetry: func(attempt int, err error, backoff time.Duration) {
			attemptCount = attempt
			authErrors = append(authErrors, err)
			metrics.authRetriesTotal.WithLabelValues("retry").Inc()

			logger.Warn("vault authentication failed, retrying",
				observability.Int("attempt", attempt),
				observability.Duration("backoff", backoff),
				observability.Error(err),
			)
		},
	}

	err := retry.Do(ctx, retryCfg, func() error {
		return vaultClient.Authenticate(ctx)
	}, retryOpts)

	if err != nil {
		metrics.authRetriesTotal.WithLabelValues("exhausted").Inc()

		// Build aggregated error message
		errMsg := fmt.Sprintf("failed to authenticate with vault after %d attempts", attemptCount+1)
		if len(authErrors) > 0 {
			errMsg += ": "
			for i, e := range authErrors {
				if i > 0 {
					errMsg += "; "
				}
				errMsg += fmt.Sprintf("attempt %d: %v", i+1, e)
			}
		}
		errMsg += fmt.Sprintf("; final error: %v", err)

		return errors.New(errMsg)
	}

	metrics.authRetriesTotal.WithLabelValues("success").Inc()
	logger.Info("vault authentication successful")

	return nil
}

// GetCertificate returns a certificate for the given request.
// It checks the cache first and issues a new certificate from Vault if needed.
// Automatic rotation is triggered when a cached certificate is expiring within
// the configured RotateBefore duration.
func (p *vaultProvider) GetCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	// Check context cancellation at the start
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	if req == nil || req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	p.mu.RLock()
	cert, ok := p.certs[req.CommonName]
	p.mu.RUnlock()

	if ok && cert.IsValid() && !cert.IsExpiringSoon(p.config.RotateBefore) {
		return cert, nil
	}

	// Check context again before expensive Vault operation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled before certificate issuance: %w", err)
	}

	// Issue new certificate from Vault (handles both initial issuance and auto-rotation)
	return p.issueCertificate(ctx, req)
}

// GetCA returns the CA certificate pool from Vault PKI.
func (p *vaultProvider) GetCA(ctx context.Context) (*x509.CertPool, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	return p.vaultClient.PKI().GetCA(ctx, p.config.PKIMount)
}

// RotateCertificate rotates the certificate for the given request.
// Unlike GetCertificate, this always issues a new certificate regardless of cache state.
func (p *vaultProvider) RotateCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	// Check context cancellation at the start
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context canceled: %w", err)
	}

	if p.closed.Load() {
		return nil, fmt.Errorf("certificate provider is closed")
	}

	if req == nil || req.CommonName == "" {
		return nil, fmt.Errorf("common name is required")
	}

	return p.issueCertificate(ctx, req)
}

// Close closes the certificate provider.
func (p *vaultProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed.Store(true)
	p.certs = nil

	if p.vaultClient != nil {
		return p.vaultClient.Close()
	}

	return nil
}

// issueCertificate issues a new certificate from Vault PKI.
func (p *vaultProvider) issueCertificate(ctx context.Context, req *CertificateRequest) (*Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ttl := p.config.TTL
	if req.TTL > 0 {
		ttl = req.TTL
	}

	vaultCert, err := p.vaultClient.PKI().IssueCertificate(ctx, &vault.PKIIssueOptions{
		Mount:      p.config.PKIMount,
		Role:       p.config.Role,
		CommonName: req.CommonName,
		AltNames:   req.DNSNames,
		IPSANs:     req.IPAddresses,
		TTL:        ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to issue certificate from vault: %w", err)
	}

	certificate := &Certificate{
		Certificate:    vaultCert.Certificate,
		PrivateKey:     vaultCert.PrivateKey,
		CertificatePEM: []byte(vaultCert.CertificatePEM),
		PrivateKeyPEM:  []byte(vaultCert.PrivateKeyPEM),
		CAChainPEM:     []byte(vaultCert.CAChainPEM),
		SerialNumber:   vaultCert.SerialNumber,
		Expiration:     vaultCert.Expiration,
	}

	// Cache the certificate
	p.certs[req.CommonName] = certificate

	p.logger.Info("certificate issued from vault",
		observability.String("common_name", req.CommonName),
		observability.Time("expiration", certificate.Expiration),
	)

	return certificate, nil
}

// Ensure vaultProvider implements Manager.
var _ Manager = (*vaultProvider)(nil)

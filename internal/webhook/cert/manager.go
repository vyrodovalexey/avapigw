// Package cert provides self-signed certificate generation and management for webhooks.
package cert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ManagerConfig holds configuration for the certificate manager.
type ManagerConfig struct {
	// ServiceName is the name of the webhook service.
	ServiceName string

	// ServiceNamespace is the namespace of the webhook service.
	ServiceNamespace string

	// SecretName is the name of the Kubernetes secret to store certificates.
	SecretName string

	// CertDir is the directory to write certificates for the webhook server.
	CertDir string

	// Validity is the certificate validity period.
	Validity time.Duration

	// RotationThreshold is the time before expiry to trigger rotation.
	RotationThreshold time.Duration

	// CheckInterval is the interval for checking certificate rotation.
	CheckInterval time.Duration

	// KeySize is the RSA key size (default 2048).
	KeySize int

	// DNSNames are additional DNS names for the server certificate.
	DNSNames []string

	// ValidatingWebhookConfigName is the name of the ValidatingWebhookConfiguration to update.
	ValidatingWebhookConfigName string

	// MutatingWebhookConfigName is the name of the MutatingWebhookConfiguration to update.
	MutatingWebhookConfigName string
}

// Validate validates the manager configuration.
func (c *ManagerConfig) Validate() error {
	if c.ServiceName == "" {
		return fmt.Errorf("service name is required")
	}
	if c.ServiceNamespace == "" {
		return fmt.Errorf("service namespace is required")
	}
	if c.SecretName == "" {
		return fmt.Errorf("secret name is required")
	}
	if c.CertDir == "" {
		return fmt.Errorf("cert directory is required")
	}
	if c.Validity <= 0 {
		c.Validity = DefaultValidity
	}
	if c.RotationThreshold <= 0 {
		c.RotationThreshold = DefaultRotationThreshold
	}
	if c.CheckInterval <= 0 {
		c.CheckInterval = DefaultCheckInterval
	}
	if c.KeySize == 0 {
		c.KeySize = DefaultKeySize
	}
	return nil
}

// Manager coordinates certificate generation, rotation, and injection.
type Manager struct {
	config    *ManagerConfig
	generator *Generator
	rotator   *Rotator
	injector  *Injector
	client    client.Client
	logger    *zap.Logger
	mu        sync.RWMutex
	started   bool
	stopCh    chan struct{}
}

// NewManager creates a new certificate manager.
func NewManager(cfg *ManagerConfig, k8sClient client.Client, logger *zap.Logger) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create generator
	generatorCfg := &GeneratorConfig{
		ServiceName:      cfg.ServiceName,
		ServiceNamespace: cfg.ServiceNamespace,
		DNSNames:         cfg.DNSNames,
		Validity:         cfg.Validity,
		KeySize:          cfg.KeySize,
	}
	generator := NewGenerator(generatorCfg)

	// Create rotator
	rotatorCfg := &RotatorConfig{
		SecretName:        cfg.SecretName,
		SecretNamespace:   cfg.ServiceNamespace,
		CertDir:           cfg.CertDir,
		RotationThreshold: cfg.RotationThreshold,
		CheckInterval:     cfg.CheckInterval,
	}
	rotator := NewRotator(rotatorCfg, generator, k8sClient, logger)

	// Create injector
	injectorCfg := &InjectorConfig{
		Namespace:                   cfg.ServiceNamespace,
		ValidatingWebhookConfigName: cfg.ValidatingWebhookConfigName,
		MutatingWebhookConfigName:   cfg.MutatingWebhookConfigName,
	}
	injector := NewInjector(injectorCfg, k8sClient, logger)

	return &Manager{
		config:    cfg,
		generator: generator,
		rotator:   rotator,
		injector:  injector,
		client:    k8sClient,
		logger:    logger.Named("cert-manager"),
		stopCh:    make(chan struct{}),
	}, nil
}

// Start starts the certificate manager.
// It ensures certificates exist, injects CA bundle into webhooks, and starts rotation monitoring.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return fmt.Errorf("certificate manager already started")
	}
	m.started = true
	m.mu.Unlock()

	m.logger.Info("starting certificate manager",
		zap.String("serviceName", m.config.ServiceName),
		zap.String("serviceNamespace", m.config.ServiceNamespace),
		zap.String("secretName", m.config.SecretName),
		zap.String("certDir", m.config.CertDir),
		zap.Duration("validity", m.config.Validity),
		zap.Duration("rotationThreshold", m.config.RotationThreshold),
		zap.Duration("checkInterval", m.config.CheckInterval),
	)

	// Register callback to inject CA bundle when certificates are rotated
	m.rotator.OnRotate(func(bundle *CertificateBundle) {
		m.logger.Info("certificates rotated, injecting CA bundle into webhooks")
		m.injector.SetCABundle(bundle.CACert)
		if err := m.injector.InjectAll(ctx); err != nil {
			m.logger.Error("failed to inject CA bundle after rotation", zap.Error(err))
		}
	})

	// Start the rotator (this ensures certificates exist)
	if err := m.rotator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start certificate rotator: %w", err)
	}

	// Get CA bundle and inject into webhooks
	caBundle := m.rotator.GetCABundle()
	if caBundle == nil {
		return fmt.Errorf("CA bundle is nil after starting rotator")
	}

	m.injector.SetCABundle(caBundle)
	if err := m.injector.InjectAll(ctx); err != nil {
		m.logger.Warn("failed to inject CA bundle into webhooks", zap.Error(err))
		// Don't return error here - webhooks might not exist yet
	}

	m.logger.Info("certificate manager started successfully")
	return nil
}

// Stop stops the certificate manager.
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		return nil
	}

	m.logger.Info("stopping certificate manager")
	close(m.stopCh)

	if err := m.rotator.Stop(); err != nil {
		return fmt.Errorf("failed to stop rotator: %w", err)
	}

	m.started = false
	m.logger.Info("certificate manager stopped")
	return nil
}

// GetCertDir returns the certificate directory path.
func (m *Manager) GetCertDir() string {
	return m.config.CertDir
}

// GetCABundle returns the current CA bundle.
func (m *Manager) GetCABundle() []byte {
	return m.rotator.GetCABundle()
}

// GetCurrentBundle returns the current certificate bundle.
func (m *Manager) GetCurrentBundle() *CertificateBundle {
	return m.rotator.GetCurrentBundle()
}

// EnsureCertificates ensures certificates exist and are valid.
func (m *Manager) EnsureCertificates(ctx context.Context) error {
	return m.rotator.EnsureCertificates(ctx)
}

// InjectCABundle injects the CA bundle into webhook configurations.
func (m *Manager) InjectCABundle(ctx context.Context) error {
	caBundle := m.rotator.GetCABundle()
	if caBundle == nil {
		return fmt.Errorf("CA bundle is not available")
	}

	m.injector.SetCABundle(caBundle)
	return m.injector.InjectAll(ctx)
}

// IsStarted returns whether the manager has been started.
func (m *Manager) IsStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}

// GetCertificateExpiry returns the expiration time of the current certificate.
func (m *Manager) GetCertificateExpiry() (time.Time, error) {
	bundle := m.rotator.GetCurrentBundle()
	if bundle == nil {
		return time.Time{}, fmt.Errorf("no certificate bundle available")
	}
	return bundle.ExpiresAt, nil
}

// NeedsRotation checks if the current certificate needs rotation.
func (m *Manager) NeedsRotation() (bool, error) {
	bundle := m.rotator.GetCurrentBundle()
	if bundle == nil {
		return true, nil // No certificate means we need to generate one
	}
	return NeedsRotation(bundle.ServerCert, m.config.RotationThreshold)
}

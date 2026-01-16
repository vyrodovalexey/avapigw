package cert

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DefaultCheckInterval is the default interval for checking certificate rotation.
	DefaultCheckInterval = 1 * time.Hour

	// SecretKeyCACert is the key for CA certificate in the secret.
	SecretKeyCACert = "ca.crt"

	// SecretKeyCAKey is the key for CA private key in the secret.
	SecretKeyCAKey = "ca.key"

	// SecretKeyTLSCert is the key for server certificate in the secret.
	SecretKeyTLSCert = "tls.crt"

	// SecretKeyTLSKey is the key for server private key in the secret.
	SecretKeyTLSKey = "tls.key"

	// CertFileName is the filename for the server certificate.
	CertFileName = "tls.crt"

	// KeyFileName is the filename for the server private key.
	KeyFileName = "tls.key"
)

// RotatorConfig holds configuration for the certificate rotator.
type RotatorConfig struct {
	// SecretName is the name of the Kubernetes secret to store certificates.
	SecretName string

	// SecretNamespace is the namespace of the Kubernetes secret.
	SecretNamespace string

	// CertDir is the directory to write certificates for the webhook server.
	CertDir string

	// RotationThreshold is the time before expiry to trigger rotation.
	RotationThreshold time.Duration

	// CheckInterval is the interval for checking certificate rotation.
	CheckInterval time.Duration
}

// Validate validates the rotator configuration.
func (c *RotatorConfig) Validate() error {
	if c.SecretName == "" {
		return fmt.Errorf("secret name is required")
	}
	if c.SecretNamespace == "" {
		return fmt.Errorf("secret namespace is required")
	}
	if c.CertDir == "" {
		return fmt.Errorf("cert directory is required")
	}
	if c.RotationThreshold <= 0 {
		return fmt.Errorf("rotation threshold must be positive")
	}
	if c.CheckInterval <= 0 {
		return fmt.Errorf("check interval must be positive")
	}
	return nil
}

// Rotator handles certificate rotation for webhooks.
type Rotator struct {
	generator         *Generator
	client            client.Client
	config            *RotatorConfig
	logger            *zap.Logger
	mu                sync.RWMutex
	currentBundle     *CertificateBundle
	stopCh            chan struct{}
	onRotateCallbacks []func(*CertificateBundle)
}

// NewRotator creates a new certificate rotator.
func NewRotator(cfg *RotatorConfig, generator *Generator, k8sClient client.Client, logger *zap.Logger) *Rotator {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = DefaultCheckInterval
	}
	if cfg.RotationThreshold == 0 {
		cfg.RotationThreshold = DefaultRotationThreshold
	}

	return &Rotator{
		generator: generator,
		client:    k8sClient,
		config:    cfg,
		logger:    logger.Named("cert-rotator"),
		stopCh:    make(chan struct{}),
	}
}

// OnRotate registers a callback to be called when certificates are rotated.
func (r *Rotator) OnRotate(callback func(*CertificateBundle)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRotateCallbacks = append(r.onRotateCallbacks, callback)
}

// Start starts the certificate rotation loop.
func (r *Rotator) Start(ctx context.Context) error {
	r.logger.Info("starting certificate rotator",
		zap.String("secretName", r.config.SecretName),
		zap.String("secretNamespace", r.config.SecretNamespace),
		zap.Duration("checkInterval", r.config.CheckInterval),
		zap.Duration("rotationThreshold", r.config.RotationThreshold),
	)

	// Ensure certificates exist on startup
	if err := r.EnsureCertificates(ctx); err != nil {
		return fmt.Errorf("failed to ensure certificates on startup: %w", err)
	}

	// Start rotation check loop
	go r.rotationLoop(ctx)

	return nil
}

// Stop stops the certificate rotator.
func (r *Rotator) Stop() error {
	r.logger.Info("stopping certificate rotator")
	close(r.stopCh)
	return nil
}

// rotationLoop periodically checks and rotates certificates if needed.
func (r *Rotator) rotationLoop(ctx context.Context) {
	ticker := time.NewTicker(r.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("rotation loop stopped due to context cancellation")
			return
		case <-r.stopCh:
			r.logger.Info("rotation loop stopped")
			return
		case <-ticker.C:
			rotated, err := r.RotateIfNeeded(ctx)
			if err != nil {
				r.logger.Error("failed to check/rotate certificates", zap.Error(err))
				recordCertRotationError()
			} else if rotated {
				r.logger.Info("certificates rotated successfully")
				recordCertRotation()
			}
		}
	}
}

// EnsureCertificates ensures certificates exist and are valid.
// If certificates don't exist or are invalid, new ones are generated.
func (r *Rotator) EnsureCertificates(ctx context.Context) error {
	r.logger.Info("ensuring certificates exist and are valid")

	// Try to load existing certificates from secret
	bundle, err := r.loadFromSecret(ctx)
	if err != nil {
		if !errors.IsNotFound(err) {
			r.logger.Warn("failed to load certificates from secret, will generate new ones", zap.Error(err))
		} else {
			r.logger.Info("certificate secret not found, will generate new certificates")
		}
		bundle = nil
	}

	// Check if existing certificates are valid
	if bundle != nil {
		valid, err := IsCertificateValid(bundle.ServerCert)
		if err != nil {
			r.logger.Warn("failed to validate existing certificate, will generate new ones", zap.Error(err))
			bundle = nil
		} else if !valid {
			r.logger.Info("existing certificate is invalid or expired, will generate new ones")
			bundle = nil
		}
	}

	// Generate new certificates if needed
	if bundle == nil {
		r.logger.Info("generating new certificates")
		bundle, err = r.generator.Generate()
		if err != nil {
			return fmt.Errorf("failed to generate certificates: %w", err)
		}

		// Save to secret
		if err := r.saveToSecret(ctx, bundle); err != nil {
			return fmt.Errorf("failed to save certificates to secret: %w", err)
		}

		recordCertGeneration()
	}

	// Write certificates to disk
	if err := r.WriteCertificatesToDir(bundle); err != nil {
		return fmt.Errorf("failed to write certificates to directory: %w", err)
	}

	// Update current bundle
	r.mu.Lock()
	r.currentBundle = bundle
	r.mu.Unlock()

	// Update metrics
	updateCertExpiry(bundle.ExpiresAt)

	r.logger.Info("certificates ensured successfully",
		zap.Time("expiresAt", bundle.ExpiresAt),
	)

	return nil
}

// checkRotationNeeded checks if the current bundle needs rotation.
// Returns true if rotation is needed, false otherwise.
func (r *Rotator) checkRotationNeeded(bundle *CertificateBundle) (bool, error) {
	needsRotation, err := NeedsRotation(bundle.ServerCert, r.config.RotationThreshold)
	if err != nil {
		return false, fmt.Errorf("failed to check if rotation is needed: %w", err)
	}

	if !needsRotation {
		r.logger.Debug("certificates do not need rotation",
			zap.Time("expiresAt", bundle.ExpiresAt),
			zap.Duration("rotationThreshold", r.config.RotationThreshold),
		)
	}

	return needsRotation, nil
}

// performRotation generates new certificates, saves them, and updates the current bundle.
func (r *Rotator) performRotation(ctx context.Context, currentExpiresAt time.Time) (*CertificateBundle, error) {
	r.logger.Info("certificates need rotation, generating new ones",
		zap.Time("currentExpiresAt", currentExpiresAt),
	)

	newBundle, err := r.generator.Generate()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new certificates: %w", err)
	}

	if err := r.saveToSecret(ctx, newBundle); err != nil {
		return nil, fmt.Errorf("failed to save new certificates to secret: %w", err)
	}

	if err := r.WriteCertificatesToDir(newBundle); err != nil {
		return nil, fmt.Errorf("failed to write new certificates to directory: %w", err)
	}

	return newBundle, nil
}

// updateBundleAndNotify updates the current bundle and notifies callbacks.
func (r *Rotator) updateBundleAndNotify(newBundle *CertificateBundle) {
	r.mu.Lock()
	r.currentBundle = newBundle
	callbacks := r.onRotateCallbacks
	r.mu.Unlock()

	updateCertExpiry(newBundle.ExpiresAt)

	for _, callback := range callbacks {
		callback(newBundle)
	}

	r.logger.Info("certificates rotated successfully",
		zap.Time("newExpiresAt", newBundle.ExpiresAt),
	)
}

// RotateIfNeeded checks if certificates need rotation and rotates them if necessary.
// Returns true if certificates were rotated.
func (r *Rotator) RotateIfNeeded(ctx context.Context) (bool, error) {
	r.mu.RLock()
	bundle := r.currentBundle
	r.mu.RUnlock()

	if bundle == nil {
		if err := r.EnsureCertificates(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	needsRotation, err := r.checkRotationNeeded(bundle)
	if err != nil {
		return false, err
	}

	if !needsRotation {
		return false, nil
	}

	newBundle, err := r.performRotation(ctx, bundle.ExpiresAt)
	if err != nil {
		return false, err
	}

	r.updateBundleAndNotify(newBundle)
	return true, nil
}

// WriteCertificatesToDir writes certificates to the certificate directory.
func (r *Rotator) WriteCertificatesToDir(bundle *CertificateBundle) error {
	// Ensure directory exists
	// G301: Certificate directory needs to be accessible by the webhook server process
	if err := os.MkdirAll(r.config.CertDir, 0o750); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write server certificate
	certPath := filepath.Join(r.config.CertDir, CertFileName)
	// G306: Certificate files need to be readable by the webhook server
	if err := os.WriteFile(certPath, bundle.ServerCert, 0o600); err != nil {
		return fmt.Errorf("failed to write server certificate: %w", err)
	}

	// Write server private key
	keyPath := filepath.Join(r.config.CertDir, KeyFileName)
	if err := os.WriteFile(keyPath, bundle.ServerKey, 0o600); err != nil {
		return fmt.Errorf("failed to write server private key: %w", err)
	}

	r.logger.Debug("certificates written to directory",
		zap.String("certDir", r.config.CertDir),
	)

	return nil
}

// loadFromSecret loads certificates from the Kubernetes secret.
func (r *Rotator) loadFromSecret(ctx context.Context) (*CertificateBundle, error) {
	secret := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      r.config.SecretName,
		Namespace: r.config.SecretNamespace,
	}, secret)
	if err != nil {
		return nil, err
	}

	// Extract certificates from secret
	caCert, ok := secret.Data[SecretKeyCACert]
	if !ok {
		return nil, fmt.Errorf("CA certificate not found in secret")
	}

	caKey, ok := secret.Data[SecretKeyCAKey]
	if !ok {
		return nil, fmt.Errorf("CA private key not found in secret")
	}

	serverCert, ok := secret.Data[SecretKeyTLSCert]
	if !ok {
		return nil, fmt.Errorf("server certificate not found in secret")
	}

	serverKey, ok := secret.Data[SecretKeyTLSKey]
	if !ok {
		return nil, fmt.Errorf("server private key not found in secret")
	}

	// Get expiry time
	expiresAt, err := GetCertificateExpiry(serverCert)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate expiry: %w", err)
	}

	return &CertificateBundle{
		CACert:     caCert,
		CAKey:      caKey,
		ServerCert: serverCert,
		ServerKey:  serverKey,
		ExpiresAt:  expiresAt,
	}, nil
}

// saveToSecret saves certificates to the Kubernetes secret.
func (r *Rotator) saveToSecret(ctx context.Context, bundle *CertificateBundle) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      r.config.SecretName,
			Namespace: r.config.SecretNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "avapigw",
				"app.kubernetes.io/component":  "webhook-certs",
				"app.kubernetes.io/managed-by": "avapigw-operator",
			},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			SecretKeyCACert:  bundle.CACert,
			SecretKeyCAKey:   bundle.CAKey,
			SecretKeyTLSCert: bundle.ServerCert,
			SecretKeyTLSKey:  bundle.ServerKey,
		},
	}

	// Try to get existing secret
	existing := &corev1.Secret{}
	err := r.client.Get(ctx, types.NamespacedName{
		Name:      r.config.SecretName,
		Namespace: r.config.SecretNamespace,
	}, existing)

	if err != nil {
		if errors.IsNotFound(err) {
			// Create new secret
			r.logger.Info("creating certificate secret",
				zap.String("name", r.config.SecretName),
				zap.String("namespace", r.config.SecretNamespace),
			)
			if err := r.client.Create(ctx, secret); err != nil {
				return fmt.Errorf("failed to create secret: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to get existing secret: %w", err)
	}

	// Update existing secret
	existing.Data = secret.Data
	existing.Labels = secret.Labels
	r.logger.Info("updating certificate secret",
		zap.String("name", r.config.SecretName),
		zap.String("namespace", r.config.SecretNamespace),
	)
	if err := r.client.Update(ctx, existing); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// GetCurrentBundle returns the current certificate bundle.
func (r *Rotator) GetCurrentBundle() *CertificateBundle {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentBundle
}

// GetCABundle returns the current CA certificate bundle for injection.
func (r *Rotator) GetCABundle() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.currentBundle == nil {
		return nil
	}
	return r.currentBundle.CACert
}

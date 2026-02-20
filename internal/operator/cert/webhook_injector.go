// Package cert provides certificate management for the operator.
package cert

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// WebhookInjectorConfig contains configuration for the webhook CA injector.
type WebhookInjectorConfig struct {
	// WebhookConfigName is the name of the ValidatingWebhookConfiguration to update.
	WebhookConfigName string

	// CertManager is the certificate manager to get the CA bundle from.
	CertManager Manager

	// Client is the Kubernetes client for updating webhook configurations.
	Client client.Client

	// RefreshInterval is the interval at which to check and refresh the CA bundle.
	// Default is 1 hour.
	RefreshInterval time.Duration

	// MetricsRegisterer is the Prometheus registerer for webhook injector metrics.
	// If nil, metrics are registered with the default registerer.
	MetricsRegisterer prometheus.Registerer
}

// webhookInjectorMetrics contains Prometheus metrics for webhook CA injection.
type webhookInjectorMetrics struct {
	injectionsTotal   *prometheus.CounterVec
	injectionDuration prometheus.Histogram
	lastInjectionTime prometheus.Gauge
}

var (
	webhookInjectorMetricsInstance *webhookInjectorMetrics
	webhookInjectorMetricsOnce     sync.Once
)

// initWebhookInjectorMetrics initializes the singleton webhook injector metrics instance
// with the given Prometheus registerer. If registerer is nil, metrics are registered
// with the default registerer. Must be called before getWebhookInjectorMetrics for
// metrics to appear on the correct registry; subsequent calls are no-ops (sync.Once).
func initWebhookInjectorMetrics(registerer prometheus.Registerer) {
	webhookInjectorMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		webhookInjectorMetricsInstance = newWebhookInjectorMetricsWithFactory(promauto.With(registerer))
	})
}

// InitWebhookInjectorMetrics initializes the singleton webhook injector metrics instance
// with the given Prometheus registerer. This is the exported wrapper for initWebhookInjectorMetrics.
func InitWebhookInjectorMetrics(registerer prometheus.Registerer) {
	initWebhookInjectorMetrics(registerer)
}

// getWebhookInjectorMetrics returns the singleton instance of webhook injector metrics.
// If initWebhookInjectorMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getWebhookInjectorMetrics() *webhookInjectorMetrics {
	initWebhookInjectorMetrics(nil)
	return webhookInjectorMetricsInstance
}

// newWebhookInjectorMetricsWithFactory creates webhook injector metrics using the given promauto factory.
func newWebhookInjectorMetricsWithFactory(factory promauto.Factory) *webhookInjectorMetrics {
	return &webhookInjectorMetrics{
		injectionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "ca_injections_total",
				Help:      "Total number of webhook CA bundle injection attempts",
			},
			[]string{"result"},
		),
		injectionDuration: factory.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "ca_injection_duration_seconds",
				Help:      "Duration of webhook CA bundle injection operations",
				Buckets:   prometheus.DefBuckets,
			},
		),
		lastInjectionTime: factory.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "last_ca_injection_timestamp",
				Help:      "Timestamp of the last successful CA bundle injection",
			},
		),
	}
}

// InitWebhookInjectorVecMetrics pre-populates all webhookInjectorMetrics vector metrics
// with common label combinations so they appear on /metrics immediately with zero values.
func InitWebhookInjectorVecMetrics() {
	m := getWebhookInjectorMetrics()

	for _, r := range []string{"success", "error"} {
		m.injectionsTotal.WithLabelValues(r)
	}
}

// WebhookCAInjector injects CA bundles into ValidatingWebhookConfiguration resources.
// It supports self-signed and Vault PKI modes by reading the CA from the certificate manager.
type WebhookCAInjector struct {
	config  *WebhookInjectorConfig
	logger  observability.Logger
	metrics *webhookInjectorMetrics

	mu       sync.RWMutex
	caBundle []byte
	stopCh   chan struct{}
	stopped  bool
}

// NewWebhookCAInjector creates a new webhook CA injector.
func NewWebhookCAInjector(config *WebhookInjectorConfig) (*WebhookCAInjector, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.WebhookConfigName == "" {
		return nil, fmt.Errorf("webhook config name is required")
	}

	if config.CertManager == nil {
		return nil, fmt.Errorf("certificate manager is required")
	}

	if config.Client == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if config.RefreshInterval == 0 {
		config.RefreshInterval = 1 * time.Hour
	}

	initWebhookInjectorMetrics(config.MetricsRegisterer)

	return &WebhookCAInjector{
		config:  config,
		logger:  observability.GetGlobalLogger().With(observability.String("component", "webhook-ca-injector")),
		metrics: getWebhookInjectorMetrics(),
		stopCh:  make(chan struct{}),
	}, nil
}

// InjectCABundle injects the CA bundle into the webhook configuration.
// This should be called at operator startup to ensure webhooks work immediately.
func (w *WebhookCAInjector) InjectCABundle(ctx context.Context) error {
	start := time.Now()
	defer func() {
		w.metrics.injectionDuration.Observe(time.Since(start).Seconds())
	}()

	// Get CA pool from certificate manager
	caPool, err := w.config.CertManager.GetCA(ctx)
	if err != nil {
		w.metrics.injectionsTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to get CA from certificate manager: %w", err)
	}

	// Get the CA certificate PEM
	// For self-signed provider, we need to get a certificate to access the CA chain
	cert, err := w.config.CertManager.GetCertificate(ctx, &CertificateRequest{
		CommonName: "webhook-ca-injector",
		DNSNames:   []string{"localhost"},
	})
	if err != nil {
		w.metrics.injectionsTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to get certificate for CA chain: %w", err)
	}

	var caBundlePEM []byte
	if len(cert.CAChainPEM) > 0 {
		caBundlePEM = cert.CAChainPEM
	} else if caPool != nil {
		// CAChainPEM is not populated; this should not happen for properly
		// configured providers (self-signed populates it from the CA cert,
		// Vault populates it from the CA chain). Log a warning and reject
		// the leaf certificate to avoid injecting the wrong bundle.
		w.logger.Warn("certificate has no CA chain PEM; cannot inject leaf certificate as CA bundle")
	}

	if len(caBundlePEM) == 0 {
		w.metrics.injectionsTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("no CA bundle available from certificate manager")
	}

	// Store the CA bundle
	w.mu.Lock()
	w.caBundle = caBundlePEM
	w.mu.Unlock()

	// Update the webhook configuration
	if err := w.updateWebhookConfiguration(ctx, caBundlePEM); err != nil {
		w.metrics.injectionsTotal.WithLabelValues("error").Inc()
		return fmt.Errorf("failed to update webhook configuration: %w", err)
	}

	w.metrics.injectionsTotal.WithLabelValues("success").Inc()
	w.metrics.lastInjectionTime.SetToCurrentTime()

	w.logger.Info("CA bundle injected into webhook configuration",
		observability.String("webhook_config", w.config.WebhookConfigName),
		observability.Int("ca_bundle_size", len(caBundlePEM)),
	)

	return nil
}

// updateWebhookConfiguration updates the ValidatingWebhookConfiguration with the CA bundle.
func (w *WebhookCAInjector) updateWebhookConfiguration(ctx context.Context, caBundlePEM []byte) error {
	// Get the current webhook configuration
	webhookConfig := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	namespacedName := types.NamespacedName{Name: w.config.WebhookConfigName}
	if err := w.config.Client.Get(ctx, namespacedName, webhookConfig); err != nil {
		return fmt.Errorf("failed to get webhook configuration: %w", err)
	}

	// Use the CA bundle PEM directly for the webhook configuration
	caBundle := caBundlePEM

	// Update each webhook's CA bundle
	updated := false
	for i := range webhookConfig.Webhooks {
		// Only update if the CA bundle is different or empty
		if !bytes.Equal(webhookConfig.Webhooks[i].ClientConfig.CABundle, caBundle) {
			webhookConfig.Webhooks[i].ClientConfig.CABundle = caBundle
			updated = true
		}
	}

	if !updated {
		w.logger.Debug("webhook CA bundle already up to date",
			observability.String("webhook_config", w.config.WebhookConfigName),
		)
		return nil
	}

	// Update the webhook configuration
	if err := w.config.Client.Update(ctx, webhookConfig); err != nil {
		return fmt.Errorf("failed to update webhook configuration: %w", err)
	}

	return nil
}

// Start starts the background CA bundle refresh loop.
// This ensures the CA bundle is kept up to date if certificates are rotated.
func (w *WebhookCAInjector) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.stopped {
		w.mu.Unlock()
		return fmt.Errorf("webhook CA injector has been stopped")
	}
	w.mu.Unlock()

	// Initial injection
	if err := w.InjectCABundle(ctx); err != nil {
		w.logger.Error("initial CA bundle injection failed",
			observability.Error(err),
		)
		// Don't return error - continue with refresh loop
	}

	// Start refresh loop
	go w.refreshLoop(ctx)

	return nil
}

// refreshLoop periodically refreshes the CA bundle.
func (w *WebhookCAInjector) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(w.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("webhook CA injector context canceled, stopping refresh loop")
			return
		case <-w.stopCh:
			w.logger.Info("webhook CA injector stopped")
			return
		case <-ticker.C:
			if err := w.InjectCABundle(ctx); err != nil {
				w.logger.Error("failed to refresh CA bundle",
					observability.Error(err),
				)
			}
		}
	}
}

// Stop stops the webhook CA injector.
func (w *WebhookCAInjector) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stopped {
		return
	}

	w.stopped = true
	close(w.stopCh)
}

// GetCABundle returns the current CA bundle.
func (w *WebhookCAInjector) GetCABundle() []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.caBundle
}

// GetCABundleBase64 returns the current CA bundle as a base64-encoded string.
func (w *WebhookCAInjector) GetCABundleBase64() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if len(w.caBundle) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(w.caBundle)
}

// Ensure WebhookCAInjector implements the expected interface.
var _ interface {
	InjectCABundle(ctx context.Context) error
	Start(ctx context.Context) error
	Stop()
	GetCABundle() []byte
	GetCABundleBase64() string
} = (*WebhookCAInjector)(nil)

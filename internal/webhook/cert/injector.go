package cert

import (
	"bytes"
	"context"
	"fmt"

	"go.uber.org/zap"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// WebhookConfigLabelKey is the label key used to identify webhook configurations managed by avapigw.
	WebhookConfigLabelKey = "app.kubernetes.io/managed-by"

	// WebhookConfigLabelValue is the label value used to identify webhook configurations managed by avapigw.
	WebhookConfigLabelValue = "avapigw-operator"
)

// InjectorConfig holds configuration for the CA bundle injector.
type InjectorConfig struct {
	// Namespace is the namespace where the operator is running.
	Namespace string

	// ValidatingWebhookConfigName is the name of the ValidatingWebhookConfiguration to update.
	// If empty, all ValidatingWebhookConfigurations with the managed-by label will be updated.
	ValidatingWebhookConfigName string

	// MutatingWebhookConfigName is the name of the MutatingWebhookConfiguration to update.
	// If empty, all MutatingWebhookConfigurations with the managed-by label will be updated.
	MutatingWebhookConfigName string
}

// Validate validates the injector configuration.
func (c *InjectorConfig) Validate() error {
	if c.Namespace == "" {
		return fmt.Errorf("namespace is required")
	}
	return nil
}

// Injector injects CA bundle into webhook configurations.
type Injector struct {
	client   client.Client
	config   *InjectorConfig
	caBundle []byte
	logger   *zap.Logger
}

// NewInjector creates a new CA bundle injector.
func NewInjector(cfg *InjectorConfig, k8sClient client.Client, logger *zap.Logger) *Injector {
	return &Injector{
		client: k8sClient,
		config: cfg,
		logger: logger.Named("cert-injector"),
	}
}

// SetCABundle sets the CA bundle to inject into webhook configurations.
func (i *Injector) SetCABundle(caBundle []byte) {
	i.caBundle = caBundle
}

// InjectIntoValidatingWebhooks injects the CA bundle into ValidatingWebhookConfigurations.
func (i *Injector) InjectIntoValidatingWebhooks(ctx context.Context) error {
	if len(i.caBundle) == 0 {
		return fmt.Errorf("CA bundle is not set")
	}

	// If a specific name is configured, update only that one
	if i.config.ValidatingWebhookConfigName != "" {
		return i.injectIntoValidatingWebhook(ctx, i.config.ValidatingWebhookConfigName)
	}

	// Otherwise, list and update all matching webhook configurations
	webhookList := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	if err := i.client.List(ctx, webhookList); err != nil {
		recordValidatingWebhookInjection(false)
		return fmt.Errorf("failed to list ValidatingWebhookConfigurations: %w", err)
	}

	var lastErr error
	injectedCount := 0
	for _, webhook := range webhookList.Items {
		// Check if this webhook is managed by avapigw
		if !i.isManaged(&webhook) {
			continue
		}

		if err := i.injectIntoValidatingWebhook(ctx, webhook.Name); err != nil {
			i.logger.Error("failed to inject CA bundle into ValidatingWebhookConfiguration",
				zap.String("name", webhook.Name),
				zap.Error(err),
			)
			lastErr = err
		} else {
			injectedCount++
		}
	}

	i.logger.Info("injected CA bundle into ValidatingWebhookConfigurations",
		zap.Int("count", injectedCount),
	)

	return lastErr
}

// injectIntoValidatingWebhook injects the CA bundle into a specific ValidatingWebhookConfiguration.
func (i *Injector) injectIntoValidatingWebhook(ctx context.Context, name string) error {
	webhook := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	if err := i.client.Get(ctx, client.ObjectKey{Name: name}, webhook); err != nil {
		recordValidatingWebhookInjection(false)
		return fmt.Errorf("failed to get ValidatingWebhookConfiguration %s: %w", name, err)
	}

	// Update CA bundle for all webhooks in the configuration
	updated := false
	for idx := range webhook.Webhooks {
		if webhook.Webhooks[idx].ClientConfig.CABundle == nil ||
			!bytes.Equal(webhook.Webhooks[idx].ClientConfig.CABundle, i.caBundle) {
			webhook.Webhooks[idx].ClientConfig.CABundle = i.caBundle
			updated = true
		}
	}

	if !updated {
		i.logger.Debug("ValidatingWebhookConfiguration already has correct CA bundle",
			zap.String("name", name),
		)
		return nil
	}

	if err := i.client.Update(ctx, webhook); err != nil {
		recordValidatingWebhookInjection(false)
		return fmt.Errorf("failed to update ValidatingWebhookConfiguration %s: %w", name, err)
	}

	recordValidatingWebhookInjection(true)
	i.logger.Info("injected CA bundle into ValidatingWebhookConfiguration",
		zap.String("name", name),
	)

	return nil
}

// InjectIntoMutatingWebhooks injects the CA bundle into MutatingWebhookConfigurations.
func (i *Injector) InjectIntoMutatingWebhooks(ctx context.Context) error {
	if len(i.caBundle) == 0 {
		return fmt.Errorf("CA bundle is not set")
	}

	// If a specific name is configured, update only that one
	if i.config.MutatingWebhookConfigName != "" {
		return i.injectIntoMutatingWebhook(ctx, i.config.MutatingWebhookConfigName)
	}

	// Otherwise, list and update all matching webhook configurations
	webhookList := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	if err := i.client.List(ctx, webhookList); err != nil {
		recordMutatingWebhookInjection(false)
		return fmt.Errorf("failed to list MutatingWebhookConfigurations: %w", err)
	}

	var lastErr error
	injectedCount := 0
	for _, webhook := range webhookList.Items {
		// Check if this webhook is managed by avapigw
		if !i.isManaged(&webhook) {
			continue
		}

		if err := i.injectIntoMutatingWebhook(ctx, webhook.Name); err != nil {
			i.logger.Error("failed to inject CA bundle into MutatingWebhookConfiguration",
				zap.String("name", webhook.Name),
				zap.Error(err),
			)
			lastErr = err
		} else {
			injectedCount++
		}
	}

	i.logger.Info("injected CA bundle into MutatingWebhookConfigurations",
		zap.Int("count", injectedCount),
	)

	return lastErr
}

// injectIntoMutatingWebhook injects the CA bundle into a specific MutatingWebhookConfiguration.
func (i *Injector) injectIntoMutatingWebhook(ctx context.Context, name string) error {
	webhook := &admissionregistrationv1.MutatingWebhookConfiguration{}
	if err := i.client.Get(ctx, client.ObjectKey{Name: name}, webhook); err != nil {
		recordMutatingWebhookInjection(false)
		return fmt.Errorf("failed to get MutatingWebhookConfiguration %s: %w", name, err)
	}

	// Update CA bundle for all webhooks in the configuration
	updated := false
	for idx := range webhook.Webhooks {
		if webhook.Webhooks[idx].ClientConfig.CABundle == nil ||
			!bytes.Equal(webhook.Webhooks[idx].ClientConfig.CABundle, i.caBundle) {
			webhook.Webhooks[idx].ClientConfig.CABundle = i.caBundle
			updated = true
		}
	}

	if !updated {
		i.logger.Debug("MutatingWebhookConfiguration already has correct CA bundle",
			zap.String("name", name),
		)
		return nil
	}

	if err := i.client.Update(ctx, webhook); err != nil {
		recordMutatingWebhookInjection(false)
		return fmt.Errorf("failed to update MutatingWebhookConfiguration %s: %w", name, err)
	}

	recordMutatingWebhookInjection(true)
	i.logger.Info("injected CA bundle into MutatingWebhookConfiguration",
		zap.String("name", name),
	)

	return nil
}

// InjectAll injects the CA bundle into all webhook configurations.
func (i *Injector) InjectAll(ctx context.Context) error {
	var errs []error

	if err := i.InjectIntoValidatingWebhooks(ctx); err != nil {
		errs = append(errs, fmt.Errorf("validating webhooks: %w", err))
	}

	if err := i.InjectIntoMutatingWebhooks(ctx); err != nil {
		errs = append(errs, fmt.Errorf("mutating webhooks: %w", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to inject CA bundle: %v", errs)
	}

	return nil
}

// isManaged checks if a webhook configuration is managed by avapigw.
func (i *Injector) isManaged(obj client.Object) bool {
	labels := obj.GetLabels()
	if labels == nil {
		return false
	}

	// Check for the managed-by label
	if value, ok := labels[WebhookConfigLabelKey]; ok && value == WebhookConfigLabelValue {
		return true
	}

	// Also check for app.kubernetes.io/name = avapigw
	if value, ok := labels["app.kubernetes.io/name"]; ok && value == "avapigw" {
		return true
	}

	return false
}

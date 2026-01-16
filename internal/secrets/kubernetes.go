package secrets

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"go.uber.org/zap"
)

// KubernetesProviderConfig holds configuration for the Kubernetes secrets provider
type KubernetesProviderConfig struct {
	// Client is the Kubernetes client
	Client client.Client
	// DefaultNamespace is the default namespace for secrets without explicit namespace
	DefaultNamespace string
	// Logger is the logger instance
	Logger *zap.Logger
}

// KubernetesProvider implements the Provider interface using Kubernetes Secrets
type KubernetesProvider struct {
	client           client.Client
	defaultNamespace string
	logger           *zap.Logger
}

// NewKubernetesProvider creates a new Kubernetes secrets provider
func NewKubernetesProvider(cfg *KubernetesProviderConfig) (*KubernetesProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: config is required", ErrProviderNotConfigured)
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("%w: kubernetes client is required", ErrProviderNotConfigured)
	}

	defaultNs := cfg.DefaultNamespace
	if defaultNs == "" {
		defaultNs = "default"
	}

	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	return &KubernetesProvider{
		client:           cfg.Client,
		defaultNamespace: defaultNs,
		logger:           logger,
	}, nil
}

// Type returns the provider type
func (p *KubernetesProvider) Type() ProviderType {
	return ProviderTypeKubernetes
}

// parsePath parses a secret path into namespace and name
// Supported formats:
// - "secret-name" -> uses default namespace
// - "namespace/secret-name" -> uses specified namespace
func (p *KubernetesProvider) parsePath(path string) (namespace, name string, err error) {
	if path == "" {
		return "", "", ErrInvalidPath
	}

	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 1 {
		return p.defaultNamespace, parts[0], nil
	}
	if parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: invalid path format: %s", ErrInvalidPath, path)
	}
	return parts[0], parts[1], nil
}

// convertK8sSecretToSecret converts a Kubernetes secret to our Secret type.
func (p *KubernetesProvider) convertK8sSecretToSecret(secret *corev1.Secret, namespace, name string) *Secret {
	result := &Secret{
		Name:      name,
		Namespace: namespace,
		Data:      secret.Data,
		Metadata:  make(map[string]string),
	}

	for k, v := range secret.Labels {
		result.Metadata["label."+k] = v
	}
	for k, v := range secret.Annotations {
		result.Metadata["annotation."+k] = v
	}

	createdAt := secret.CreationTimestamp.Time
	result.CreatedAt = &createdAt
	result.Version = secret.ResourceVersion

	return result
}

// GetSecret retrieves a secret by path
func (p *KubernetesProvider) GetSecret(ctx context.Context, path string) (*Secret, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "get", time.Since(start), nil)
	}()

	namespace, name, err := p.parsePath(path)
	if err != nil {
		RecordOperation(p.Type(), "get", time.Since(start), err)
		return nil, err
	}

	p.logger.Debug("Getting Kubernetes secret",
		zap.String("namespace", namespace),
		zap.String("name", name),
	)

	secret := &corev1.Secret{}
	if err := p.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		if errors.IsNotFound(err) {
			p.logger.Debug("Secret not found",
				zap.String("namespace", namespace),
				zap.String("name", name),
			)
			RecordOperation(p.Type(), "get", time.Since(start), ErrSecretNotFound)
			return nil, fmt.Errorf("%w: %s/%s", ErrSecretNotFound, namespace, name)
		}
		p.logger.Error("Failed to get secret",
			zap.String("namespace", namespace),
			zap.String("name", name),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "get", time.Since(start), err)
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, name, err)
	}

	result := p.convertK8sSecretToSecret(secret, namespace, name)

	p.logger.Debug("Successfully retrieved secret",
		zap.String("namespace", namespace),
		zap.String("name", name),
		zap.Int("keys", len(result.Data)),
	)

	return result, nil
}

// ListSecrets lists secrets in a namespace
func (p *KubernetesProvider) ListSecrets(ctx context.Context, path string) ([]string, error) {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "list", time.Since(start), nil)
	}()

	// Path is the namespace, or empty for default namespace
	namespace := path
	if namespace == "" {
		namespace = p.defaultNamespace
	}

	p.logger.Debug("Listing Kubernetes secrets",
		zap.String("namespace", namespace),
	)

	secretList := &corev1.SecretList{}
	if err := p.client.List(ctx, secretList, client.InNamespace(namespace)); err != nil {
		p.logger.Error("Failed to list secrets",
			zap.String("namespace", namespace),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "list", time.Since(start), err)
		return nil, fmt.Errorf("failed to list secrets in namespace %s: %w", namespace, err)
	}

	names := make([]string, 0, len(secretList.Items))
	for _, secret := range secretList.Items {
		names = append(names, secret.Name)
	}

	p.logger.Debug("Successfully listed secrets",
		zap.String("namespace", namespace),
		zap.Int("count", len(names)),
	)

	return names, nil
}

// createOrUpdateK8sSecret creates or updates a Kubernetes secret.
func (p *KubernetesProvider) createOrUpdateK8sSecret(
	ctx context.Context,
	secret *corev1.Secret,
	namespace, name string,
	start time.Time,
) error {
	existingSecret := &corev1.Secret{}
	err := p.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, existingSecret)
	secretExists := err == nil

	if secretExists {
		secret.ResourceVersion = existingSecret.ResourceVersion
		if err := p.client.Update(ctx, secret); err != nil {
			p.logger.Error("Failed to update secret",
				zap.String("namespace", namespace),
				zap.String("name", name),
				zap.Error(err),
			)
			RecordOperation(p.Type(), "write", time.Since(start), err)
			return fmt.Errorf("failed to update secret %s/%s: %w", namespace, name, err)
		}
		p.logger.Info("Updated secret",
			zap.String("namespace", namespace),
			zap.String("name", name),
		)
	} else {
		if err := p.client.Create(ctx, secret); err != nil {
			p.logger.Error("Failed to create secret",
				zap.String("namespace", namespace),
				zap.String("name", name),
				zap.Error(err),
			)
			RecordOperation(p.Type(), "write", time.Since(start), err)
			return fmt.Errorf("failed to create secret %s/%s: %w", namespace, name, err)
		}
		p.logger.Info("Created secret",
			zap.String("namespace", namespace),
			zap.String("name", name),
		)
	}

	return nil
}

// WriteSecret creates or updates a secret
func (p *KubernetesProvider) WriteSecret(ctx context.Context, path string, data map[string][]byte) error {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "write", time.Since(start), nil)
	}()

	namespace, name, err := p.parsePath(path)
	if err != nil {
		RecordOperation(p.Type(), "write", time.Since(start), err)
		return err
	}

	p.logger.Debug("Writing Kubernetes secret",
		zap.String("namespace", namespace),
		zap.String("name", name),
	)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	return p.createOrUpdateK8sSecret(ctx, secret, namespace, name, start)
}

// DeleteSecret deletes a secret
func (p *KubernetesProvider) DeleteSecret(ctx context.Context, path string) error {
	start := time.Now()
	defer func() {
		RecordOperation(p.Type(), "delete", time.Since(start), nil)
	}()

	namespace, name, err := p.parsePath(path)
	if err != nil {
		RecordOperation(p.Type(), "delete", time.Since(start), err)
		return err
	}

	p.logger.Debug("Deleting Kubernetes secret",
		zap.String("namespace", namespace),
		zap.String("name", name),
	)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	if err := p.client.Delete(ctx, secret); err != nil {
		if errors.IsNotFound(err) {
			p.logger.Debug("Secret not found for deletion",
				zap.String("namespace", namespace),
				zap.String("name", name),
			)
			return nil // Not an error if already deleted
		}
		p.logger.Error("Failed to delete secret",
			zap.String("namespace", namespace),
			zap.String("name", name),
			zap.Error(err),
		)
		RecordOperation(p.Type(), "delete", time.Since(start), err)
		return fmt.Errorf("failed to delete secret %s/%s: %w", namespace, name, err)
	}

	p.logger.Info("Deleted secret",
		zap.String("namespace", namespace),
		zap.String("name", name),
	)

	return nil
}

// IsReadOnly returns false as Kubernetes secrets support writes
func (p *KubernetesProvider) IsReadOnly() bool {
	return false
}

// HealthCheck checks if the Kubernetes API is accessible
func (p *KubernetesProvider) HealthCheck(ctx context.Context) error {
	start := time.Now()

	// Try to list secrets in the default namespace (limited to 1)
	secretList := &corev1.SecretList{}
	if err := p.client.List(ctx, secretList, client.InNamespace(p.defaultNamespace), client.Limit(1)); err != nil {
		p.logger.Error("Kubernetes provider health check failed", zap.Error(err))
		RecordHealthStatus(p.Type(), false)
		RecordOperation(p.Type(), "health_check", time.Since(start), err)
		return fmt.Errorf("kubernetes API health check failed: %w", err)
	}

	RecordHealthStatus(p.Type(), true)
	RecordOperation(p.Type(), "health_check", time.Since(start), nil)
	return nil
}

// Close cleans up provider resources
func (p *KubernetesProvider) Close() error {
	p.logger.Debug("Closing Kubernetes secrets provider")
	return nil
}

package vault

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// KVClient provides KV secrets engine operations.
type KVClient interface {
	// Read reads a secret from KV.
	Read(ctx context.Context, mount, path string) (map[string]interface{}, error)

	// Write writes a secret to KV.
	Write(ctx context.Context, mount, path string, data map[string]interface{}) error

	// Delete deletes a secret from KV.
	Delete(ctx context.Context, mount, path string) error

	// List lists secrets at a path.
	List(ctx context.Context, mount, path string) ([]string, error)
}

// kvClient implements KVClient.
type kvClient struct {
	client *vaultClient
}

// newKVClient creates a new KV client.
func newKVClient(client *vaultClient) *kvClient {
	return &kvClient{client: client}
}

// Read reads a secret from KV.
func (k *kvClient) Read(ctx context.Context, mount, path string) (map[string]interface{}, error) {
	if mount == "" {
		return nil, NewVaultError("kv_read", "", "mount is required")
	}

	if path == "" {
		return nil, NewVaultError("kv_read", "", "path is required")
	}

	start := time.Now()
	fullPath := fmt.Sprintf("%s/data/%s", mount, path)

	// Check cache first
	if k.client.cache != nil {
		if cached, ok := k.client.cache.get(fullPath); ok {
			k.client.metrics.RecordCacheHit()
			if data, ok := cached.(map[string]interface{}); ok {
				return data, nil
			}
		}
		k.client.metrics.RecordCacheMiss()
	}

	// Execute with retry
	var secret interface{}
	err := k.client.executeWithRetry(ctx, func() error {
		var err error
		secret, err = k.client.api.Logical().ReadWithContext(ctx, fullPath)
		return err
	})

	if err != nil {
		k.client.metrics.RecordRequest("kv_read", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("kv_read", fullPath, "failed to read secret", err)
	}

	vaultSecret, ok := secret.(*vaultapi.Secret)
	if !ok || vaultSecret == nil {
		k.client.metrics.RecordRequest("kv_read", "error", time.Since(start))
		return nil, WrapError(ErrSecretNotFound, fullPath)
	}

	if vaultSecret.Data == nil {
		k.client.metrics.RecordRequest("kv_read", "error", time.Since(start))
		return nil, WrapError(ErrSecretNotFound, fullPath)
	}

	// KV v2 wraps data in a "data" key
	// Check if the data key exists and is not nil (deleted secrets have data: null)
	dataValue, hasData := vaultSecret.Data["data"]
	if hasData && dataValue == nil {
		// Secret was deleted (soft delete in KV v2)
		k.client.metrics.RecordRequest("kv_read", "error", time.Since(start))
		return nil, WrapError(ErrSecretNotFound, fullPath)
	}

	data, ok := dataValue.(map[string]interface{})
	if !ok {
		// Try KV v1 format
		data = vaultSecret.Data
	}

	// Cache the result
	if k.client.cache != nil {
		k.client.cache.set(fullPath, data)
	}

	k.client.metrics.RecordRequest("kv_read", "success", time.Since(start))
	k.client.logger.Debug("secret read",
		observability.String("path", fullPath),
	)

	return data, nil
}

// Write writes a secret to KV.
func (k *kvClient) Write(ctx context.Context, mount, path string, data map[string]interface{}) error {
	if mount == "" {
		return NewVaultError("kv_write", "", "mount is required")
	}

	if path == "" {
		return NewVaultError("kv_write", "", "path is required")
	}

	if data == nil {
		return NewVaultError("kv_write", "", "data is required")
	}

	start := time.Now()
	fullPath := fmt.Sprintf("%s/data/%s", mount, path)

	// KV v2 requires data to be wrapped
	wrappedData := map[string]interface{}{
		"data": data,
	}

	// Execute with retry
	err := k.client.executeWithRetry(ctx, func() error {
		_, err := k.client.api.Logical().WriteWithContext(ctx, fullPath, wrappedData)
		return err
	})

	if err != nil {
		k.client.metrics.RecordRequest("kv_write", "error", time.Since(start))
		return NewVaultErrorWithCause("kv_write", fullPath, "failed to write secret", err)
	}

	// Invalidate cache
	if k.client.cache != nil {
		k.client.cache.delete(fullPath)
	}

	k.client.metrics.RecordRequest("kv_write", "success", time.Since(start))
	k.client.logger.Debug("secret written",
		observability.String("path", fullPath),
	)

	return nil
}

// Delete deletes a secret from KV.
func (k *kvClient) Delete(ctx context.Context, mount, path string) error {
	if mount == "" {
		return NewVaultError("kv_delete", "", "mount is required")
	}

	if path == "" {
		return NewVaultError("kv_delete", "", "path is required")
	}

	start := time.Now()
	fullPath := fmt.Sprintf("%s/data/%s", mount, path)

	// Execute with retry
	err := k.client.executeWithRetry(ctx, func() error {
		_, err := k.client.api.Logical().DeleteWithContext(ctx, fullPath)
		return err
	})

	if err != nil {
		k.client.metrics.RecordRequest("kv_delete", "error", time.Since(start))
		return NewVaultErrorWithCause("kv_delete", fullPath, "failed to delete secret", err)
	}

	// Invalidate cache
	if k.client.cache != nil {
		k.client.cache.delete(fullPath)
	}

	k.client.metrics.RecordRequest("kv_delete", "success", time.Since(start))
	k.client.logger.Debug("secret deleted",
		observability.String("path", fullPath),
	)

	return nil
}

// List lists secrets at a path.
func (k *kvClient) List(ctx context.Context, mount, path string) ([]string, error) {
	if mount == "" {
		return nil, NewVaultError("kv_list", "", "mount is required")
	}

	start := time.Now()
	fullPath := fmt.Sprintf("%s/metadata/%s", mount, path)

	secret, err := k.client.api.Logical().ListWithContext(ctx, fullPath)
	if err != nil {
		k.client.metrics.RecordRequest("kv_list", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("kv_list", fullPath, "failed to list secrets", err)
	}

	if secret == nil || secret.Data == nil {
		k.client.metrics.RecordRequest("kv_list", "success", time.Since(start))
		return []string{}, nil
	}

	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		k.client.metrics.RecordRequest("kv_list", "success", time.Since(start))
		return []string{}, nil
	}

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if keyStr, ok := key.(string); ok {
			result = append(result, keyStr)
		}
	}

	k.client.metrics.RecordRequest("kv_list", "success", time.Since(start))
	k.client.logger.Debug("secrets listed",
		observability.String("path", fullPath),
		observability.Int("count", len(result)),
	)

	return result, nil
}

// disabledKVClient is a KV client that returns ErrVaultDisabled.
type disabledKVClient struct{}

func (c *disabledKVClient) Read(_ context.Context, _, _ string) (map[string]interface{}, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledKVClient) Write(_ context.Context, _, _ string, _ map[string]interface{}) error {
	return ErrVaultDisabled
}

func (c *disabledKVClient) Delete(_ context.Context, _, _ string) error {
	return ErrVaultDisabled
}

func (c *disabledKVClient) List(_ context.Context, _, _ string) ([]string, error) {
	return nil, ErrVaultDisabled
}

// Ensure implementations satisfy the interface.
var (
	_ KVClient = (*kvClient)(nil)
	_ KVClient = (*disabledKVClient)(nil)
)

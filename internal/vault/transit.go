package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// TransitClient provides Transit secrets engine operations.
type TransitClient interface {
	// Encrypt encrypts data.
	Encrypt(ctx context.Context, mount, keyName string, plaintext []byte) ([]byte, error)

	// Decrypt decrypts data.
	Decrypt(ctx context.Context, mount, keyName string, ciphertext []byte) ([]byte, error)

	// Sign signs data.
	Sign(ctx context.Context, mount, keyName string, data []byte) ([]byte, error)

	// Verify verifies a signature.
	Verify(ctx context.Context, mount, keyName string, data, signature []byte) (bool, error)
}

// transitClient implements TransitClient.
type transitClient struct {
	client *vaultClient
}

// newTransitClient creates a new Transit client.
func newTransitClient(client *vaultClient) *transitClient {
	return &transitClient{client: client}
}

// Encrypt encrypts data using the Transit secrets engine.
func (t *transitClient) Encrypt(ctx context.Context, mount, keyName string, plaintext []byte) ([]byte, error) {
	if mount == "" {
		return nil, NewVaultError("transit_encrypt", "", "mount is required")
	}

	if keyName == "" {
		return nil, NewVaultError("transit_encrypt", "", "key name is required")
	}

	if len(plaintext) == 0 {
		return nil, NewVaultError("transit_encrypt", "", "plaintext is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/encrypt/%s", mount, keyName)

	// Base64 encode the plaintext
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)

	data := map[string]interface{}{
		"plaintext": encodedPlaintext,
	}

	// Execute with retry
	var secret interface{}
	err := t.client.executeWithRetry(ctx, func() error {
		var err error
		secret, err = t.client.api.Logical().WriteWithContext(ctx, path, data)
		return err
	})

	if err != nil {
		t.client.metrics.RecordRequest("transit_encrypt", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("transit_encrypt", path, "failed to encrypt data", err)
	}

	vaultSecret, ok := secret.(*vaultapi.Secret)
	if !ok || vaultSecret == nil || vaultSecret.Data == nil {
		t.client.metrics.RecordRequest("transit_encrypt", "error", time.Since(start))
		return nil, NewVaultError("transit_encrypt", path, "no data in response")
	}

	ciphertext, ok := vaultSecret.Data["ciphertext"].(string)
	if !ok {
		t.client.metrics.RecordRequest("transit_encrypt", "error", time.Since(start))
		return nil, NewVaultError("transit_encrypt", path, "ciphertext not found in response")
	}

	t.client.metrics.RecordRequest("transit_encrypt", "success", time.Since(start))
	t.client.logger.Debug("data encrypted",
		observability.String("key", keyName),
	)

	return []byte(ciphertext), nil
}

// Decrypt decrypts data using the Transit secrets engine.
func (t *transitClient) Decrypt(ctx context.Context, mount, keyName string, ciphertext []byte) ([]byte, error) {
	if mount == "" {
		return nil, NewVaultError("transit_decrypt", "", "mount is required")
	}

	if keyName == "" {
		return nil, NewVaultError("transit_decrypt", "", "key name is required")
	}

	if len(ciphertext) == 0 {
		return nil, NewVaultError("transit_decrypt", "", "ciphertext is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/decrypt/%s", mount, keyName)

	data := map[string]interface{}{
		"ciphertext": string(ciphertext),
	}

	// Execute with retry
	var secret interface{}
	err := t.client.executeWithRetry(ctx, func() error {
		var err error
		secret, err = t.client.api.Logical().WriteWithContext(ctx, path, data)
		return err
	})

	if err != nil {
		t.client.metrics.RecordRequest("transit_decrypt", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("transit_decrypt", path, "failed to decrypt data", err)
	}

	vaultSecret, ok := secret.(*vaultapi.Secret)
	if !ok || vaultSecret == nil || vaultSecret.Data == nil {
		t.client.metrics.RecordRequest("transit_decrypt", "error", time.Since(start))
		return nil, NewVaultError("transit_decrypt", path, "no data in response")
	}

	encodedPlaintext, ok := vaultSecret.Data["plaintext"].(string)
	if !ok {
		t.client.metrics.RecordRequest("transit_decrypt", "error", time.Since(start))
		return nil, NewVaultError("transit_decrypt", path, "plaintext not found in response")
	}

	// Base64 decode the plaintext
	plaintext, err := base64.StdEncoding.DecodeString(encodedPlaintext)
	if err != nil {
		t.client.metrics.RecordRequest("transit_decrypt", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("transit_decrypt", path, "failed to decode plaintext", err)
	}

	t.client.metrics.RecordRequest("transit_decrypt", "success", time.Since(start))
	t.client.logger.Debug("data decrypted",
		observability.String("key", keyName),
	)

	return plaintext, nil
}

// Sign signs data using the Transit secrets engine.
func (t *transitClient) Sign(ctx context.Context, mount, keyName string, data []byte) ([]byte, error) {
	if mount == "" {
		return nil, NewVaultError("transit_sign", "", "mount is required")
	}

	if keyName == "" {
		return nil, NewVaultError("transit_sign", "", "key name is required")
	}

	if len(data) == 0 {
		return nil, NewVaultError("transit_sign", "", "data is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/sign/%s", mount, keyName)

	// Base64 encode the input
	encodedInput := base64.StdEncoding.EncodeToString(data)

	requestData := map[string]interface{}{
		"input": encodedInput,
	}

	// Execute with retry
	var secret interface{}
	err := t.client.executeWithRetry(ctx, func() error {
		var err error
		secret, err = t.client.api.Logical().WriteWithContext(ctx, path, requestData)
		return err
	})

	if err != nil {
		t.client.metrics.RecordRequest("transit_sign", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("transit_sign", path, "failed to sign data", err)
	}

	vaultSecret, ok := secret.(*vaultapi.Secret)
	if !ok || vaultSecret == nil || vaultSecret.Data == nil {
		t.client.metrics.RecordRequest("transit_sign", "error", time.Since(start))
		return nil, NewVaultError("transit_sign", path, "no data in response")
	}

	signature, ok := vaultSecret.Data["signature"].(string)
	if !ok {
		t.client.metrics.RecordRequest("transit_sign", "error", time.Since(start))
		return nil, NewVaultError("transit_sign", path, "signature not found in response")
	}

	t.client.metrics.RecordRequest("transit_sign", "success", time.Since(start))
	t.client.logger.Debug("data signed",
		observability.String("key", keyName),
	)

	return []byte(signature), nil
}

// Verify verifies a signature using the Transit secrets engine.
func (t *transitClient) Verify(ctx context.Context, mount, keyName string, data, signature []byte) (bool, error) {
	if mount == "" {
		return false, NewVaultError("transit_verify", "", "mount is required")
	}

	if keyName == "" {
		return false, NewVaultError("transit_verify", "", "key name is required")
	}

	if len(data) == 0 {
		return false, NewVaultError("transit_verify", "", "data is required")
	}

	if len(signature) == 0 {
		return false, NewVaultError("transit_verify", "", "signature is required")
	}

	start := time.Now()
	path := fmt.Sprintf("%s/verify/%s", mount, keyName)

	// Base64 encode the input
	encodedInput := base64.StdEncoding.EncodeToString(data)

	requestData := map[string]interface{}{
		"input":     encodedInput,
		"signature": string(signature),
	}

	secret, err := t.client.api.Logical().WriteWithContext(ctx, path, requestData)
	if err != nil {
		t.client.metrics.RecordRequest("transit_verify", "error", time.Since(start))
		return false, NewVaultErrorWithCause("transit_verify", path, "failed to verify signature", err)
	}

	if secret == nil || secret.Data == nil {
		t.client.metrics.RecordRequest("transit_verify", "error", time.Since(start))
		return false, NewVaultError("transit_verify", path, "no data in response")
	}

	valid, ok := secret.Data["valid"].(bool)
	if !ok {
		t.client.metrics.RecordRequest("transit_verify", "error", time.Since(start))
		return false, NewVaultError("transit_verify", path, "valid flag not found in response")
	}

	t.client.metrics.RecordRequest("transit_verify", "success", time.Since(start))
	t.client.logger.Debug("signature verified",
		observability.String("key", keyName),
		observability.Bool("valid", valid),
	)

	return valid, nil
}

// disabledTransitClient is a Transit client that returns ErrVaultDisabled.
type disabledTransitClient struct{}

func (c *disabledTransitClient) Encrypt(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledTransitClient) Decrypt(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledTransitClient) Sign(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
	return nil, ErrVaultDisabled
}

func (c *disabledTransitClient) Verify(_ context.Context, _, _ string, _, _ []byte) (bool, error) {
	return false, ErrVaultDisabled
}

// Ensure implementations satisfy the interface.
var (
	_ TransitClient = (*transitClient)(nil)
	_ TransitClient = (*disabledTransitClient)(nil)
)

package vault

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// authenticateWithToken authenticates using a direct token.
func (c *vaultClient) authenticateWithToken(_ context.Context) error {
	if c.config.Token == "" {
		return NewAuthenticationError("token", "token is empty")
	}

	c.api.SetToken(c.config.Token)

	// Lookup token to get TTL
	secret, err := c.api.Auth().Token().LookupSelf()
	if err != nil {
		return NewAuthenticationErrorWithCause("token", "failed to lookup token", err)
	}

	if secret != nil && secret.Data != nil {
		if ttl, ok := secret.Data["ttl"]; ok {
			// Handle both json.Number (from Vault API) and float64 (from tests)
			ttlSeconds := extractTTLSeconds(ttl)
			if ttlSeconds > 0 {
				c.tokenTTL.Store(ttlSeconds)
				c.tokenExpiry.Store(time.Now().Add(time.Duration(ttlSeconds) * time.Second).Unix())
				c.metrics.SetTokenTTL(float64(ttlSeconds))
			}
		}
	}

	c.logger.Debug("authenticated with token")
	return nil
}

// extractTTLSeconds extracts TTL seconds from various numeric types.
// The Vault API may return json.Number, float64, or int depending on context.
func extractTTLSeconds(ttl interface{}) int64 {
	switch v := ttl.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return int64(f)
		}
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

// authenticateWithKubernetes authenticates using Kubernetes ServiceAccount JWT.
func (c *vaultClient) authenticateWithKubernetes(ctx context.Context) error {
	if c.config.Kubernetes == nil {
		return NewAuthenticationError("kubernetes", "kubernetes configuration is nil")
	}

	tokenPath := c.config.Kubernetes.GetTokenPath()
	jwt, err := os.ReadFile(tokenPath) // #nosec G304 -- token path from trusted config
	if err != nil {
		return NewAuthenticationErrorWithCause("kubernetes", "failed to read service account token", err)
	}

	mountPath := c.config.Kubernetes.GetMountPath()
	path := "auth/" + mountPath + "/login"

	data := map[string]interface{}{
		"role": c.config.Kubernetes.Role,
		"jwt":  string(jwt),
	}

	secret, err := c.api.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return NewAuthenticationErrorWithCause("kubernetes", "failed to authenticate", err)
	}

	if secret == nil || secret.Auth == nil {
		return NewAuthenticationError("kubernetes", "no auth info in response")
	}

	c.api.SetToken(secret.Auth.ClientToken)
	c.tokenTTL.Store(int64(secret.Auth.LeaseDuration))
	c.tokenExpiry.Store(time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second).Unix())
	c.metrics.SetTokenTTL(float64(secret.Auth.LeaseDuration))

	c.logger.Debug("authenticated with kubernetes",
		observability.String("role", c.config.Kubernetes.Role),
		observability.Int64("ttl_seconds", int64(secret.Auth.LeaseDuration)),
	)

	return nil
}

// authenticateWithAppRole authenticates using AppRole.
func (c *vaultClient) authenticateWithAppRole(ctx context.Context) error {
	if c.config.AppRole == nil {
		return NewAuthenticationError("approle", "approle configuration is nil")
	}

	mountPath := c.config.AppRole.GetMountPath()
	path := "auth/" + mountPath + "/login"

	data := map[string]interface{}{
		"role_id":   c.config.AppRole.RoleID,
		"secret_id": c.config.AppRole.SecretID,
	}

	secret, err := c.api.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return NewAuthenticationErrorWithCause("approle", "failed to authenticate", err)
	}

	if secret == nil || secret.Auth == nil {
		return NewAuthenticationError("approle", "no auth info in response")
	}

	c.api.SetToken(secret.Auth.ClientToken)
	c.tokenTTL.Store(int64(secret.Auth.LeaseDuration))
	c.tokenExpiry.Store(time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second).Unix())
	c.metrics.SetTokenTTL(float64(secret.Auth.LeaseDuration))

	c.logger.Debug("authenticated with approle",
		observability.Int64("ttl_seconds", int64(secret.Auth.LeaseDuration)),
	)

	return nil
}

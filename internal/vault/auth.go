package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
)

// ErrInvalidAuthConfig is returned when auth configuration is invalid.
var ErrInvalidAuthConfig = errors.New("invalid auth configuration")

const (
	// DefaultServiceAccountTokenPath is the default path to the service account token.
	// This is the standard Kubernetes service account token path, not a hardcoded credential.
	//nolint:gosec // G101: This is a standard Kubernetes path, not a credential
	DefaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// DefaultKubernetesMountPath is the default mount path for Kubernetes auth.
	DefaultKubernetesMountPath = "kubernetes"

	// DefaultAppRoleMountPath is the default mount path for AppRole auth.
	DefaultAppRoleMountPath = "approle"
)

// AuthMethod defines the interface for Vault authentication methods.
type AuthMethod interface {
	// Authenticate authenticates with Vault and returns the auth secret.
	Authenticate(ctx context.Context, client *vault.Client) (*vault.Secret, error)

	// Name returns the name of the authentication method.
	Name() string
}

// KubernetesAuth implements Kubernetes authentication for Vault.
type KubernetesAuth struct {
	role               string
	serviceAccountPath string
	mountPath          string
}

// NewKubernetesAuth creates a new Kubernetes authentication method.
func NewKubernetesAuth(role, mountPath string) (*KubernetesAuth, error) {
	if role == "" {
		return nil, fmt.Errorf("%w: role is required", ErrInvalidAuthConfig)
	}
	if mountPath == "" {
		mountPath = DefaultKubernetesMountPath
	}

	return &KubernetesAuth{
		role:               role,
		serviceAccountPath: DefaultServiceAccountTokenPath,
		mountPath:          mountPath,
	}, nil
}

// NewKubernetesAuthWithTokenPath creates a new Kubernetes authentication method with a custom token path.
func NewKubernetesAuthWithTokenPath(role, mountPath, tokenPath string) (*KubernetesAuth, error) {
	if role == "" {
		return nil, fmt.Errorf("%w: role is required", ErrInvalidAuthConfig)
	}
	if mountPath == "" {
		mountPath = DefaultKubernetesMountPath
	}
	if tokenPath == "" {
		tokenPath = DefaultServiceAccountTokenPath
	}

	return &KubernetesAuth{
		role:               role,
		serviceAccountPath: tokenPath,
		mountPath:          mountPath,
	}, nil
}

// Authenticate implements AuthMethod.
func (a *KubernetesAuth) Authenticate(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	if client == nil {
		return nil, fmt.Errorf("kubernetes auth failed: vault client is nil")
	}

	// Check context before file operation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("kubernetes auth failed: %w", ctx.Err())
	default:
	}

	// Read the service account token
	jwt, err := os.ReadFile(a.serviceAccountPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}

	// Authenticate with Vault
	path := fmt.Sprintf("auth/%s/login", a.mountPath)
	data := map[string]interface{}{
		"role": a.role,
		"jwt":  string(jwt),
	}

	secret, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("kubernetes auth failed: %w", err)
	}

	return secret, nil
}

// Name implements AuthMethod.
func (a *KubernetesAuth) Name() string {
	return "kubernetes"
}

// TokenAuth implements token-based authentication for Vault.
type TokenAuth struct {
	token string
}

// NewTokenAuth creates a new token authentication method.
func NewTokenAuth(token string) (*TokenAuth, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token is required", ErrInvalidAuthConfig)
	}
	return &TokenAuth{
		token: token,
	}, nil
}

// Authenticate implements AuthMethod.
func (a *TokenAuth) Authenticate(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	if client == nil {
		return nil, fmt.Errorf("token auth failed: vault client is nil")
	}

	// Set the token directly
	client.SetToken(a.token)

	// Verify the token by looking up self
	secret, err := client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("token auth failed: %w", err)
	}

	// Create an auth response similar to other auth methods
	authSecret := &vault.Secret{
		Auth: &vault.SecretAuth{
			ClientToken: a.token,
			Renewable:   false,
		},
	}

	// Extract lease duration from token lookup
	if secret != nil && secret.Data != nil {
		// Handle both float64 and json.Number types
		switch ttl := secret.Data["ttl"].(type) {
		case float64:
			authSecret.Auth.LeaseDuration = int(ttl)
		case json.Number:
			if v, err := ttl.Int64(); err == nil {
				authSecret.Auth.LeaseDuration = int(v)
			}
		}

		if renewable, ok := secret.Data["renewable"].(bool); ok {
			authSecret.Auth.Renewable = renewable
		}
	}

	return authSecret, nil
}

// Name implements AuthMethod.
func (a *TokenAuth) Name() string {
	return "token"
}

// AppRoleAuth implements AppRole authentication for Vault.
type AppRoleAuth struct {
	roleID    string
	secretID  string
	mountPath string
}

// NewAppRoleAuth creates a new AppRole authentication method.
func NewAppRoleAuth(roleID, secretID, mountPath string) (*AppRoleAuth, error) {
	if roleID == "" {
		return nil, fmt.Errorf("%w: roleID is required", ErrInvalidAuthConfig)
	}
	if secretID == "" {
		return nil, fmt.Errorf("%w: secretID is required", ErrInvalidAuthConfig)
	}
	if mountPath == "" {
		mountPath = DefaultAppRoleMountPath
	}

	return &AppRoleAuth{
		roleID:    roleID,
		secretID:  secretID,
		mountPath: mountPath,
	}, nil
}

// Authenticate implements AuthMethod.
func (a *AppRoleAuth) Authenticate(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	if client == nil {
		return nil, fmt.Errorf("approle auth failed: vault client is nil")
	}

	path := fmt.Sprintf("auth/%s/login", a.mountPath)
	data := map[string]interface{}{
		"role_id":   a.roleID,
		"secret_id": a.secretID,
	}

	secret, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("approle auth failed: %w", err)
	}

	return secret, nil
}

// Name implements AuthMethod.
func (a *AppRoleAuth) Name() string {
	return "approle"
}

// UserpassAuth implements username/password authentication for Vault.
type UserpassAuth struct {
	username  string
	password  string
	mountPath string
}

// NewUserpassAuth creates a new username/password authentication method.
func NewUserpassAuth(username, password, mountPath string) (*UserpassAuth, error) {
	if username == "" {
		return nil, fmt.Errorf("%w: username is required", ErrInvalidAuthConfig)
	}
	if password == "" {
		return nil, fmt.Errorf("%w: password is required", ErrInvalidAuthConfig)
	}
	if mountPath == "" {
		mountPath = "userpass"
	}

	return &UserpassAuth{
		username:  username,
		password:  password,
		mountPath: mountPath,
	}, nil
}

// Authenticate implements AuthMethod.
func (a *UserpassAuth) Authenticate(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	if client == nil {
		return nil, fmt.Errorf("userpass auth failed: vault client is nil")
	}

	// Validate username to prevent path injection - check original username for dangerous patterns
	if strings.Contains(a.username, "..") || strings.Contains(a.username, "/") {
		return nil, fmt.Errorf("userpass auth failed: invalid username")
	}

	// Sanitize username for URL path
	sanitizedUsername := url.PathEscape(a.username)

	path := fmt.Sprintf("auth/%s/login/%s", a.mountPath, sanitizedUsername)
	data := map[string]interface{}{
		"password": a.password,
	}

	secret, err := client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("userpass auth failed: %w", err)
	}

	return secret, nil
}

// Name implements AuthMethod.
func (a *UserpassAuth) Name() string {
	return "userpass"
}

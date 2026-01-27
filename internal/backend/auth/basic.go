package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// Default configuration values for Basic auth.
const (
	DefaultCredentialCacheTTL = 5 * time.Minute
)

// BasicProvider implements Basic authentication for backend connections.
type BasicProvider struct {
	name    string
	config  *config.BackendBasicAuthConfig
	logger  observability.Logger
	metrics *Metrics
	vault   vault.Client

	// Credential cache
	mu               sync.RWMutex
	cachedUsername   string
	cachedPassword   string
	credentialExpiry time.Time

	// Lifecycle
	closed atomic.Bool
}

// NewBasicProvider creates a new Basic authentication provider.
func NewBasicProvider(name string, cfg *config.BackendBasicAuthConfig, opts ...ProviderOption) (*BasicProvider, error) {
	if cfg == nil {
		return nil, NewConfigError("config", "Basic configuration is required")
	}

	if !cfg.Enabled {
		return nil, NewConfigError("enabled", "Basic authentication is not enabled")
	}

	if err := cfg.Validate(); err != nil {
		return nil, NewConfigErrorWithCause("config", "invalid Basic configuration", err)
	}

	p := &BasicProvider{
		name:    name,
		config:  cfg,
		logger:  observability.NopLogger(),
		metrics: NopMetrics(),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.logger = p.logger.With(
		observability.String("provider", name),
		observability.String("auth_type", "basic"),
	)

	return p, nil
}

// Name returns the provider name.
func (p *BasicProvider) Name() string {
	return p.name
}

// Type returns the authentication type.
func (p *BasicProvider) Type() string {
	return "basic"
}

// ApplyHTTP applies Basic authentication to an HTTP request.
func (p *BasicProvider) ApplyHTTP(ctx context.Context, req *http.Request) error {
	if p.closed.Load() {
		return ErrProviderClosed
	}

	start := time.Now()

	username, password, err := p.getCredentials(ctx)
	if err != nil {
		p.metrics.RecordRequest(p.name, "basic", "error", time.Since(start))
		p.metrics.RecordError(p.name, "basic", "credential_acquisition")
		return NewProviderErrorWithCause(p.name, "apply_http", "failed to get credentials", err)
	}

	// Set Basic auth header
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set("Authorization", "Basic "+auth)

	p.metrics.RecordRequest(p.name, "basic", "success", time.Since(start))
	p.logger.Debug("applied Basic authentication to HTTP request")

	return nil
}

// ApplyGRPC returns gRPC dial options for Basic authentication.
func (p *BasicProvider) ApplyGRPC(ctx context.Context) ([]grpc.DialOption, error) {
	if p.closed.Load() {
		return nil, ErrProviderClosed
	}

	start := time.Now()

	username, password, err := p.getCredentials(ctx)
	if err != nil {
		p.metrics.RecordRequest(p.name, "basic", "error", time.Since(start))
		p.metrics.RecordError(p.name, "basic", "credential_acquisition")
		return nil, NewProviderErrorWithCause(p.name, "apply_grpc", "failed to get credentials", err)
	}

	creds := &basicPerRPCCredentials{
		username: username,
		password: password,
	}

	p.metrics.RecordRequest(p.name, "basic", "success", time.Since(start))
	p.logger.Debug("created gRPC credentials for Basic authentication")

	return []grpc.DialOption{
		grpc.WithPerRPCCredentials(creds),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, nil
}

// Refresh refreshes the credentials from Vault.
func (p *BasicProvider) Refresh(ctx context.Context) error {
	if p.closed.Load() {
		return ErrProviderClosed
	}

	// Only refresh if using Vault
	if p.config.VaultPath == "" {
		return nil
	}

	start := time.Now()

	// Force refresh by clearing cache
	p.mu.Lock()
	p.cachedUsername = ""
	p.cachedPassword = ""
	p.credentialExpiry = time.Time{}
	p.mu.Unlock()

	// Get new credentials
	_, _, err := p.getCredentials(ctx)
	if err != nil {
		p.metrics.RecordRefresh(p.name, "basic", "error", time.Since(start))
		return NewProviderErrorWithCause(p.name, "refresh", "failed to refresh credentials", err)
	}

	p.metrics.RecordRefresh(p.name, "basic", "success", time.Since(start))
	p.logger.Info("Basic credentials refreshed")

	return nil
}

// Close closes the provider and releases resources.
func (p *BasicProvider) Close() error {
	if p.closed.Swap(true) {
		return nil
	}

	p.logger.Info("Basic provider closed")
	return nil
}

// getCredentials returns valid credentials, using cache if available.
func (p *BasicProvider) getCredentials(
	ctx context.Context,
) (user string, pass string, err error) {
	// Check cache first
	p.mu.RLock()
	if p.cachedUsername != "" && time.Now().Before(p.credentialExpiry) {
		cachedUser, cachedPass := p.cachedUsername, p.cachedPassword
		p.mu.RUnlock()
		p.metrics.RecordCacheHit()
		return cachedUser, cachedPass, nil
	}
	p.mu.RUnlock()

	p.metrics.RecordCacheMiss()

	// Acquire write lock to fetch new credentials
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cachedUsername != "" && time.Now().Before(p.credentialExpiry) {
		return p.cachedUsername, p.cachedPassword, nil
	}

	// Fetch credentials based on source
	if p.config.VaultPath != "" {
		user, pass, err = p.getVaultCredentials(ctx)
	} else {
		user, pass, err = p.getStaticCredentials()
	}

	if err != nil {
		return "", "", err
	}

	// Cache the credentials
	p.cachedUsername = user
	p.cachedPassword = pass
	p.credentialExpiry = time.Now().Add(DefaultCredentialCacheTTL)

	p.logger.Debug("credentials acquired",
		observability.Bool("from_vault", p.config.VaultPath != ""),
	)

	return user, pass, nil
}

// getStaticCredentials returns the static credentials from configuration.
func (p *BasicProvider) getStaticCredentials() (user string, pass string, err error) {
	if p.config.Username == "" {
		return "", "", NewConfigError("username", "username is empty")
	}

	if p.config.Password == "" {
		return "", "", NewConfigError("password", "password is empty")
	}

	return p.config.Username, p.config.Password, nil
}

// getVaultCredentials retrieves credentials from Vault.
func (p *BasicProvider) getVaultCredentials(
	ctx context.Context,
) (user string, pass string, err error) {
	if p.vault == nil || !p.vault.IsEnabled() {
		return "", "", NewProviderError(p.name, "vault_credentials", "vault client not available")
	}

	// Parse vault path (format: mount/path)
	parts := strings.SplitN(p.config.VaultPath, "/", 2)
	if len(parts) != 2 {
		return "", "", NewConfigError("vaultPath", "invalid vault path format, expected mount/path")
	}

	mount, path := parts[0], parts[1]

	data, err := p.vault.KV().Read(ctx, mount, path)
	if err != nil {
		return "", "", NewProviderErrorWithCause(
			p.name, "vault_credentials", "failed to read credentials from vault", err)
	}

	usernameKey := p.config.GetEffectiveUsernameKey()
	passwordKey := p.config.GetEffectivePasswordKey()

	username, ok := data[usernameKey].(string)
	if !ok {
		return "", "", NewProviderError(p.name, "vault_credentials", "username not found in vault secret")
	}

	password, ok := data[passwordKey].(string)
	if !ok {
		return "", "", NewProviderError(p.name, "vault_credentials", "password not found in vault secret")
	}

	return username, password, nil
}

// basicPerRPCCredentials implements credentials.PerRPCCredentials for Basic auth.
type basicPerRPCCredentials struct {
	username string
	password string
}

// GetRequestMetadata returns the request metadata for gRPC.
func (c *basicPerRPCCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(c.username + ":" + c.password))
	return map[string]string{
		"authorization": "Basic " + auth,
	}, nil
}

// RequireTransportSecurity indicates whether transport security is required.
func (c *basicPerRPCCredentials) RequireTransportSecurity() bool {
	return false
}

// Ensure basicPerRPCCredentials implements credentials.PerRPCCredentials.
var _ credentials.PerRPCCredentials = (*basicPerRPCCredentials)(nil)

// Ensure BasicProvider implements Provider.
var _ Provider = (*BasicProvider)(nil)

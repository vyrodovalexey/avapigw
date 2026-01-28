package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// JWT token source constants.
const (
	TokenSourceStatic = "static"
	TokenSourceVault  = "vault"
	TokenSourceOIDC   = "oidc"
)

// Default configuration values.
const (
	DefaultTokenCacheTTL    = 5 * time.Minute
	DefaultTokenRefreshTime = 30 * time.Second
	DefaultOIDCTimeout      = 30 * time.Second
	DefaultHeaderName       = "Authorization"
	DefaultHeaderPrefix     = "Bearer"
)

// JWTProvider implements JWT authentication for backend connections.
type JWTProvider struct {
	name    string
	config  *config.BackendJWTAuthConfig
	logger  observability.Logger
	metrics *Metrics
	vault   vault.Client

	// Token cache
	mu          sync.RWMutex
	cachedToken string
	tokenExpiry time.Time

	// HTTP client for OIDC
	httpClient *http.Client

	// Lifecycle
	closed    atomic.Bool
	stopCh    chan struct{}
	stoppedCh chan struct{}
}

// NewJWTProvider creates a new JWT authentication provider.
func NewJWTProvider(name string, cfg *config.BackendJWTAuthConfig, opts ...ProviderOption) (*JWTProvider, error) {
	if cfg == nil {
		return nil, NewConfigError("config", "JWT configuration is required")
	}

	if !cfg.Enabled {
		return nil, NewConfigError("enabled", "JWT authentication is not enabled")
	}

	if err := cfg.Validate(); err != nil {
		return nil, NewConfigErrorWithCause("config", "invalid JWT configuration", err)
	}

	p := &JWTProvider{
		name:       name,
		config:     cfg,
		logger:     observability.NopLogger(),
		metrics:    NopMetrics(),
		httpClient: &http.Client{Timeout: DefaultOIDCTimeout},
		stopCh:     make(chan struct{}),
		stoppedCh:  make(chan struct{}),
	}

	for _, opt := range opts {
		opt(p)
	}

	p.logger = p.logger.With(
		observability.String("provider", name),
		observability.String("auth_type", "jwt"),
	)

	return p, nil
}

// Name returns the provider name.
func (p *JWTProvider) Name() string {
	return p.name
}

// Type returns the authentication type.
func (p *JWTProvider) Type() string {
	return "jwt"
}

// ApplyHTTP applies JWT authentication to an HTTP request.
func (p *JWTProvider) ApplyHTTP(ctx context.Context, req *http.Request) error {
	if p.closed.Load() {
		return ErrProviderClosed
	}

	start := time.Now()

	token, err := p.getToken(ctx)
	if err != nil {
		p.metrics.RecordRequest(p.name, "jwt", "error", time.Since(start))
		p.metrics.RecordError(p.name, "jwt", "token_acquisition")
		return NewProviderErrorWithCause(p.name, "apply_http", "failed to get token", err)
	}

	headerName := p.config.GetEffectiveHeaderName()
	headerPrefix := p.config.GetEffectiveHeaderPrefix()

	req.Header.Set(headerName, headerPrefix+" "+token)

	p.metrics.RecordRequest(p.name, "jwt", "success", time.Since(start))
	p.logger.Debug("applied JWT authentication to HTTP request",
		observability.String("header", headerName),
	)

	return nil
}

// ApplyGRPC returns gRPC dial options for JWT authentication.
func (p *JWTProvider) ApplyGRPC(ctx context.Context) ([]grpc.DialOption, error) {
	if p.closed.Load() {
		return nil, ErrProviderClosed
	}

	start := time.Now()

	token, err := p.getToken(ctx)
	if err != nil {
		p.metrics.RecordRequest(p.name, "jwt", "error", time.Since(start))
		p.metrics.RecordError(p.name, "jwt", "token_acquisition")
		return nil, NewProviderErrorWithCause(p.name, "apply_grpc", "failed to get token", err)
	}

	creds := &jwtPerRPCCredentials{
		token:        token,
		headerName:   p.config.GetEffectiveHeaderName(),
		headerPrefix: p.config.GetEffectiveHeaderPrefix(),
	}

	p.metrics.RecordRequest(p.name, "jwt", "success", time.Since(start))
	p.logger.Debug("created gRPC credentials for JWT authentication")

	return []grpc.DialOption{
		grpc.WithPerRPCCredentials(creds),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, nil
}

// Refresh refreshes the JWT token.
func (p *JWTProvider) Refresh(ctx context.Context) error {
	if p.closed.Load() {
		return ErrProviderClosed
	}

	start := time.Now()

	// Force refresh by clearing cache
	p.mu.Lock()
	p.cachedToken = ""
	p.tokenExpiry = time.Time{}
	p.mu.Unlock()

	// Get new token
	_, err := p.getToken(ctx)
	if err != nil {
		p.metrics.RecordRefresh(p.name, "jwt", "error", time.Since(start))
		return NewProviderErrorWithCause(p.name, "refresh", "failed to refresh token", err)
	}

	p.metrics.RecordRefresh(p.name, "jwt", "success", time.Since(start))
	p.logger.Info("JWT token refreshed")

	return nil
}

// Close closes the provider and releases resources.
func (p *JWTProvider) Close() error {
	if p.closed.Swap(true) {
		return nil
	}

	close(p.stopCh)

	p.logger.Info("JWT provider closed")
	return nil
}

// getToken returns a valid JWT token, using cache if available.
func (p *JWTProvider) getToken(ctx context.Context) (string, error) {
	// Check cache first
	p.mu.RLock()
	if p.cachedToken != "" && time.Now().Before(p.tokenExpiry.Add(-DefaultTokenRefreshTime)) {
		token := p.cachedToken
		p.mu.RUnlock()
		p.metrics.RecordCacheHit()
		return token, nil
	}
	p.mu.RUnlock()

	p.metrics.RecordCacheMiss()

	// Acquire write lock to fetch new token
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.cachedToken != "" && time.Now().Before(p.tokenExpiry.Add(-DefaultTokenRefreshTime)) {
		return p.cachedToken, nil
	}

	// Fetch new token based on source
	var token string
	var expiry time.Time
	var err error

	switch p.config.TokenSource {
	case TokenSourceStatic:
		token, expiry, err = p.getStaticToken()
	case TokenSourceVault:
		token, expiry, err = p.getVaultToken(ctx)
	case TokenSourceOIDC:
		token, expiry, err = p.getOIDCToken(ctx)
	default:
		return "", NewConfigError("tokenSource", "unsupported token source: "+p.config.TokenSource)
	}

	if err != nil {
		return "", err
	}

	// Cache the token
	p.cachedToken = token
	p.tokenExpiry = expiry
	p.metrics.SetTokenExpiry(p.name, "jwt", expiry)

	p.logger.Debug("token acquired",
		observability.String("source", p.config.TokenSource),
		observability.Time("expiry", expiry),
	)

	return token, nil
}

// getStaticToken returns the static token from configuration.
func (p *JWTProvider) getStaticToken() (string, time.Time, error) {
	if p.config.StaticToken == "" {
		return "", time.Time{}, NewConfigError("staticToken", "static token is empty")
	}

	// Static tokens don't expire, but we set a cache TTL
	expiry := time.Now().Add(DefaultTokenCacheTTL)
	return p.config.StaticToken, expiry, nil
}

// getVaultToken retrieves a token from Vault.
func (p *JWTProvider) getVaultToken(ctx context.Context) (string, time.Time, error) {
	if p.vault == nil || !p.vault.IsEnabled() {
		return "", time.Time{}, NewProviderError(p.name, "vault_token", "vault client not available")
	}

	if p.config.VaultPath == "" {
		return "", time.Time{}, NewConfigError("vaultPath", "vault path is required")
	}

	// Parse vault path (format: mount/path)
	parts := strings.SplitN(p.config.VaultPath, "/", 2)
	if len(parts) != 2 {
		return "", time.Time{}, NewConfigError("vaultPath", "invalid vault path format, expected mount/path")
	}

	mount, path := parts[0], parts[1]

	data, err := p.vault.KV().Read(ctx, mount, path)
	if err != nil {
		return "", time.Time{}, NewProviderErrorWithCause(p.name, "vault_token", "failed to read token from vault", err)
	}

	token, ok := data["token"].(string)
	if !ok {
		return "", time.Time{}, NewProviderError(p.name, "vault_token", "token not found in vault secret")
	}

	// Check for expiry in vault data
	expiry := time.Now().Add(DefaultTokenCacheTTL)
	if expiryVal, ok := data["expiry"].(string); ok {
		if parsedExpiry, err := time.Parse(time.RFC3339, expiryVal); err == nil {
			expiry = parsedExpiry
		}
	}

	return token, expiry, nil
}

// getOIDCToken retrieves a token using OIDC client credentials flow.
func (p *JWTProvider) getOIDCToken(ctx context.Context) (string, time.Time, error) {
	if p.config.OIDC == nil {
		return "", time.Time{}, NewConfigError("oidc", "OIDC configuration is required")
	}

	clientSecret, err := p.getOIDCClientSecret(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	// Discover token endpoint
	tokenEndpoint, err := p.discoverTokenEndpoint(ctx)
	if err != nil {
		return "", time.Time{}, err
	}

	// Request token using client credentials grant
	return p.requestOIDCToken(ctx, tokenEndpoint, clientSecret)
}

// getOIDCClientSecret retrieves the OIDC client secret.
func (p *JWTProvider) getOIDCClientSecret(ctx context.Context) (string, error) {
	// Try static secret first
	if p.config.OIDC.ClientSecret != "" {
		return p.config.OIDC.ClientSecret, nil
	}

	// Try Vault
	if p.config.OIDC.ClientSecretVaultPath != "" {
		if p.vault == nil || !p.vault.IsEnabled() {
			return "", NewProviderError(p.name, "oidc_secret", "vault client not available")
		}

		parts := strings.SplitN(p.config.OIDC.ClientSecretVaultPath, "/", 2)
		if len(parts) != 2 {
			return "", NewConfigError("clientSecretVaultPath", "invalid vault path format")
		}

		data, err := p.vault.KV().Read(ctx, parts[0], parts[1])
		if err != nil {
			return "", NewProviderErrorWithCause(p.name, "oidc_secret", "failed to read client secret from vault", err)
		}

		secret, ok := data["client_secret"].(string)
		if !ok {
			return "", NewProviderError(p.name, "oidc_secret", "client_secret not found in vault secret")
		}

		return secret, nil
	}

	return "", NewConfigError("clientSecret", "no client secret configured")
}

// discoverTokenEndpoint discovers the OIDC token endpoint.
func (p *JWTProvider) discoverTokenEndpoint(ctx context.Context) (string, error) {
	discoveryURL := strings.TrimSuffix(p.config.OIDC.IssuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", NewProviderErrorWithCause(p.name, "oidc_discovery", "failed to create discovery request", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", NewProviderErrorWithCause(p.name, "oidc_discovery", "failed to fetch discovery document", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("discovery request failed with status %d", resp.StatusCode)
		return "", NewProviderError(p.name, "oidc_discovery", msg)
	}

	var discovery struct {
		TokenEndpoint string `json:"token_endpoint"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", NewProviderErrorWithCause(p.name, "oidc_discovery", "failed to parse discovery document", err)
	}

	if discovery.TokenEndpoint == "" {
		return "", NewProviderError(p.name, "oidc_discovery", "token_endpoint not found in discovery document")
	}

	return discovery.TokenEndpoint, nil
}

// requestOIDCToken requests a token from the OIDC token endpoint.
func (p *JWTProvider) requestOIDCToken(
	ctx context.Context, tokenEndpoint, clientSecret string,
) (string, time.Time, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", p.config.OIDC.ClientID)
	data.Set("client_secret", clientSecret)

	if len(p.config.OIDC.Scopes) > 0 {
		data.Set("scope", strings.Join(p.config.OIDC.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", time.Time{}, NewProviderErrorWithCause(p.name, "oidc_token", "failed to create token request", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", time.Time{}, NewProviderErrorWithCause(p.name, "oidc_token", "failed to request token", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		msg := fmt.Sprintf("token request failed with status %d: %s", resp.StatusCode, string(body))
		return "", time.Time{}, NewProviderError(p.name, "oidc_token", msg)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", time.Time{}, NewProviderErrorWithCause(p.name, "oidc_token", "failed to parse token response", err)
	}

	if tokenResp.AccessToken == "" {
		return "", time.Time{}, NewProviderError(p.name, "oidc_token", "access_token not found in response")
	}

	// Calculate expiry
	expiry := time.Now().Add(DefaultTokenCacheTTL)
	if tokenResp.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	}

	// Apply custom cache TTL if configured
	if p.config.OIDC.TokenCacheTTL.Duration() > 0 && p.config.OIDC.TokenCacheTTL.Duration() < time.Until(expiry) {
		expiry = time.Now().Add(p.config.OIDC.TokenCacheTTL.Duration())
	}

	return tokenResp.AccessToken, expiry, nil
}

// jwtPerRPCCredentials implements credentials.PerRPCCredentials for JWT.
type jwtPerRPCCredentials struct {
	token        string
	headerName   string
	headerPrefix string
}

// GetRequestMetadata returns the request metadata for gRPC.
func (c *jwtPerRPCCredentials) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	headerKey := strings.ToLower(c.headerName)
	return map[string]string{
		headerKey: c.headerPrefix + " " + c.token,
	}, nil
}

// RequireTransportSecurity indicates whether transport security is required.
func (c *jwtPerRPCCredentials) RequireTransportSecurity() bool {
	return false
}

// Ensure jwtPerRPCCredentials implements credentials.PerRPCCredentials.
var _ credentials.PerRPCCredentials = (*jwtPerRPCCredentials)(nil)

// Ensure JWTProvider implements Provider.
var _ Provider = (*JWTProvider)(nil)

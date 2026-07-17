package vault

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Vault client timeout constants.
const (
	// DefaultTokenRenewalTimeout is the default timeout for token renewal operations.
	DefaultTokenRenewalTimeout = 30 * time.Second

	// DefaultCloseTimeout is the default timeout for waiting for goroutines to stop.
	DefaultCloseTimeout = 5 * time.Second

	// MinRenewalInterval is the minimum interval for token renewal.
	MinRenewalInterval = time.Minute
)

// Client provides Vault operations.
type Client interface {
	// IsEnabled returns true if Vault is enabled.
	IsEnabled() bool

	// Authenticate authenticates with Vault.
	Authenticate(ctx context.Context) error

	// RenewToken renews the current token.
	RenewToken(ctx context.Context) error

	// Health returns Vault health status.
	Health(ctx context.Context) (*HealthStatus, error)

	// PKI returns the PKI secrets engine client.
	PKI() PKIClient

	// KV returns the KV secrets engine client.
	KV() KVClient

	// Transit returns the Transit secrets engine client.
	Transit() TransitClient

	// Close closes the client.
	Close() error
}

// HealthStatus represents Vault health status.
type HealthStatus struct {
	// Initialized indicates if Vault is initialized.
	Initialized bool

	// Sealed indicates if Vault is sealed.
	Sealed bool

	// Standby indicates if this is a standby node.
	Standby bool

	// Version is the Vault version.
	Version string

	// ClusterName is the cluster name.
	ClusterName string

	// ClusterID is the cluster ID.
	ClusterID string
}

// vaultClient implements the Client interface.
type vaultClient struct {
	config  *Config
	api     *vaultapi.Client
	logger  observability.Logger
	metrics *Metrics

	// Sub-clients
	pkiClient     *pkiClient
	kvClient      *kvClient
	transitClient *transitClient

	// Cache
	cache *secretCache

	// Token management
	tokenTTL    atomic.Int64
	tokenExpiry atomic.Int64

	// Lifecycle. stopCh/stoppedCh belong to the CURRENT token-renewal
	// goroutine generation and are replaced by Authenticate under mu.
	// Goroutines never re-read these fields: they receive their own
	// generation's channels as arguments (generation capture pattern).
	mu             sync.RWMutex
	closed         bool
	stopCh         chan struct{}
	stoppedCh      chan struct{}
	renewalStarted bool // current generation running and its stopCh not yet closed

	// closeTimeout bounds the wait for a renewal goroutine generation to stop
	// (Authenticate replacement wait and Close shutdown wait). It defaults to
	// DefaultCloseTimeout and is overridable in tests (mirrors the
	// backend/health stopTimeout seam). Set before any goroutines start; never
	// mutated afterwards.
	closeTimeout time.Duration
}

// ClientOption is a functional option for configuring the client.
type ClientOption func(*vaultClient)

// WithMetrics sets the metrics recorder for the client.
func WithMetrics(metrics *Metrics) ClientOption {
	return func(c *vaultClient) {
		c.metrics = metrics
	}
}

// New creates a new Vault client.
func New(cfg *Config, logger observability.Logger, opts ...ClientOption) (Client, error) {
	if cfg == nil {
		return nil, NewConfigurationError("", "configuration is nil")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// If Vault is disabled, return a disabled client
	if !cfg.Enabled {
		return &disabledClient{}, nil
	}

	// Create Vault API config
	apiConfig := vaultapi.DefaultConfig()
	apiConfig.Address = cfg.Address

	// Configure TLS
	if cfg.TLS != nil {
		tlsConfig := &vaultapi.TLSConfig{
			CACert:        cfg.TLS.CACert,
			CAPath:        cfg.TLS.CAPath,
			ClientCert:    cfg.TLS.ClientCert,
			ClientKey:     cfg.TLS.ClientKey,
			TLSServerName: cfg.TLS.ServerName,
			Insecure:      cfg.TLS.SkipVerify,
		}
		if err := apiConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, NewConfigurationErrorWithCause("tls", "failed to configure TLS", err)
		}
	}

	// Create Vault API client
	api, err := vaultapi.NewClient(apiConfig)
	if err != nil {
		return nil, NewVaultErrorWithCause("init", "", "failed to create vault client", err)
	}

	// Set namespace if configured
	if cfg.Namespace != "" {
		api.SetNamespace(cfg.Namespace)
	}

	client := &vaultClient{
		config:       cfg,
		api:          api,
		logger:       logger.With(observability.String("component", "vault")),
		stopCh:       make(chan struct{}),
		stoppedCh:    make(chan struct{}),
		closeTimeout: DefaultCloseTimeout,
	}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Initialize metrics if not provided
	if client.metrics == nil {
		client.metrics = NewMetrics("gateway")
	}

	// Initialize cache if enabled
	if cfg.Cache != nil && cfg.Cache.Enabled {
		client.cache = newSecretCache(cfg.Cache.GetMaxSize(), cfg.Cache.GetTTL())
	}

	// Initialize sub-clients
	client.pkiClient = newPKIClient(client)
	client.kvClient = newKVClient(client)
	client.transitClient = newTransitClient(client)

	return client, nil
}

// IsEnabled returns true if Vault is enabled.
func (c *vaultClient) IsEnabled() bool {
	return true
}

// closeWaitTimeout returns the bounded wait for goroutine shutdown, falling
// back to DefaultCloseTimeout when the seam was left unset (zero value).
func (c *vaultClient) closeWaitTimeout() time.Duration {
	if c.closeTimeout > 0 {
		return c.closeTimeout
	}
	return DefaultCloseTimeout
}

// Authenticate authenticates with Vault.
func (c *vaultClient) Authenticate(ctx context.Context) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClientClosed
	}
	c.mu.RUnlock()

	// Check if context is already canceled or has expired deadline before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Context is still valid, proceed with authentication
	}

	start := time.Now()
	var err error

	switch c.config.AuthMethod {
	case AuthMethodToken:
		err = c.authenticateWithToken(ctx)
	case AuthMethodKubernetes:
		err = c.authenticateWithKubernetes(ctx)
	case AuthMethodAppRole:
		err = c.authenticateWithAppRole(ctx)
	default:
		err = NewConfigurationError("authMethod", "unsupported auth method: "+string(c.config.AuthMethod))
	}

	duration := time.Since(start)
	status := "success"
	if err != nil {
		status = "error"
		c.metrics.RecordRequest("authenticate", status, duration)
		return err
	}

	c.metrics.RecordRequest("authenticate", status, duration)
	c.logger.Info("authenticated with vault",
		observability.String("method", string(c.config.AuthMethod)),
		observability.Duration("duration", duration),
	)

	// Start the token renewal goroutine for a new generation, signaling the
	// previous generation to stop first. Channels are created per generation
	// and captured by the goroutine at spawn time (generation capture
	// pattern), so a stranded previous goroutine only ever observes and
	// closes its own generation's channels.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrClientClosed
	}
	if c.renewalStarted {
		// Signal the previous renewal goroutine to stop. Clearing
		// renewalStarted records that this generation's stop channel has
		// been closed, so Close() cannot close it a second time.
		close(c.stopCh)
		c.renewalStarted = false
		prevStoppedCh := c.stoppedCh
		c.mu.Unlock()

		// Wait (bounded) for the previous goroutine to finish. Waiting on
		// the captured channel guarantees we observe the correct generation
		// even if it only exits after this timeout fires.
		select {
		case <-prevStoppedCh:
			// Previous goroutine stopped successfully
		case <-time.After(c.closeWaitTimeout()):
			c.logger.Warn("timeout waiting for previous token renewal goroutine to stop")
		}

		c.mu.Lock()
		// Re-check closed: Close() may have run while we waited unlocked.
		if c.closed {
			c.mu.Unlock()
			return ErrClientClosed
		}
	}
	stopCh := make(chan struct{})
	stoppedCh := make(chan struct{})
	c.stopCh = stopCh
	c.stoppedCh = stoppedCh
	c.renewalStarted = true
	c.mu.Unlock()

	//nolint:contextcheck // Background goroutine manages its own context lifecycle
	go c.tokenRenewalLoop(stopCh, stoppedCh)

	return nil
}

// RenewToken renews the current token.
func (c *vaultClient) RenewToken(ctx context.Context) error {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return ErrClientClosed
	}
	c.mu.RUnlock()

	start := time.Now()

	secret, err := c.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		c.metrics.RecordRequest("renew_token", "error", time.Since(start))
		return NewVaultErrorWithCause("renew_token", "", "failed to renew token", err)
	}

	if secret != nil && secret.Auth != nil {
		c.tokenTTL.Store(int64(secret.Auth.LeaseDuration))
		c.tokenExpiry.Store(time.Now().Add(time.Duration(secret.Auth.LeaseDuration) * time.Second).Unix())
		c.metrics.SetTokenTTL(float64(secret.Auth.LeaseDuration))
	}

	c.metrics.RecordRequest("renew_token", "success", time.Since(start))
	c.logger.Debug("token renewed",
		observability.Int64("ttl_seconds", c.tokenTTL.Load()),
	)

	return nil
}

// Health returns Vault health status.
func (c *vaultClient) Health(ctx context.Context) (*HealthStatus, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, ErrClientClosed
	}
	c.mu.RUnlock()

	start := time.Now()

	health, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil {
		c.metrics.RecordRequest("health", "error", time.Since(start))
		return nil, NewVaultErrorWithCause("health", "", "failed to get health status", err)
	}

	c.metrics.RecordRequest("health", "success", time.Since(start))

	return &HealthStatus{
		Initialized: health.Initialized,
		Sealed:      health.Sealed,
		Standby:     health.Standby,
		Version:     health.Version,
		ClusterName: health.ClusterName,
		ClusterID:   health.ClusterID,
	}, nil
}

// PKI returns the PKI secrets engine client.
func (c *vaultClient) PKI() PKIClient {
	return c.pkiClient
}

// KV returns the KV secrets engine client.
func (c *vaultClient) KV() KVClient {
	return c.kvClient
}

// Transit returns the Transit secrets engine client.
func (c *vaultClient) Transit() TransitClient {
	return c.transitClient
}

// Close closes the client.
func (c *vaultClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	// Capture the current generation's channels under the lock so the wait
	// below targets the goroutine generation that is actually running, even
	// if Authenticate replaced the struct fields earlier. The renewalStarted
	// guard ensures the stop channel is closed exactly once and that Close
	// does not wait when no renewal goroutine was ever started.
	renewalRunning := c.renewalStarted
	stoppedCh := c.stoppedCh
	if renewalRunning {
		close(c.stopCh)
		c.renewalStarted = false
	}
	c.mu.Unlock()

	if renewalRunning {
		// Wait for token renewal to stop
		select {
		case <-stoppedCh:
			c.logger.Debug("token renewal goroutine stopped successfully")
		case <-time.After(c.closeWaitTimeout()):
			c.logger.Warn("timeout waiting for token renewal to stop")
		}
	}

	// Stop the cache cleanup goroutine
	if c.cache != nil {
		c.cache.stop()
	}

	c.logger.Info("vault client closed")
	return nil
}

// tokenRenewalLoop handles automatic token renewal.
// It uses stop-channel signaling for lifecycle management instead of a passed
// context to prevent goroutine leaks when the original context is short-lived.
//
// The stop/stopped channels are captured per generation at spawn time
// (generation capture pattern): Authenticate may replace c.stopCh/c.stoppedCh
// with fresh channels for a newer generation while an older goroutine is still
// draining. The older goroutine must keep selecting on its own stop channel
// and close its own stopped channel; re-reading the struct fields here would
// both race with the replacement and strand the goroutine on a channel that
// will never be closed for it.
func (c *vaultClient) tokenRenewalLoop(stopCh <-chan struct{}, stoppedCh chan<- struct{}) {
	defer close(stoppedCh)

	renewInterval := c.calculateRenewalInterval()
	if renewInterval <= 0 {
		c.logger.Debug("token renewal disabled (no TTL)")
		return
	}

	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	c.logger.Info("started token renewal loop",
		observability.Duration("interval", renewInterval),
	)

	for {
		select {
		case <-stopCh:
			c.logger.Info("token renewal stopped")
			return
		case <-ticker.C:
			c.performTokenRenewal()
			renewInterval = c.updateRenewalInterval(ticker, renewInterval)
		}
	}
}

// performTokenRenewal performs a single token renewal operation with proper context management.
func (c *vaultClient) performTokenRenewal() {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultTokenRenewalTimeout)
	defer cancel()

	c.handleTokenRenewal(ctx)
}

// calculateRenewalInterval calculates the token renewal interval based on TTL.
func (c *vaultClient) calculateRenewalInterval() time.Duration {
	ttl := c.tokenTTL.Load()
	if ttl <= 0 {
		return 0
	}

	// Renew at 2/3 of TTL
	interval := time.Duration(ttl*2/3) * time.Second
	if interval < MinRenewalInterval {
		interval = MinRenewalInterval
	}
	return interval
}

// handleTokenRenewal handles a single token renewal attempt.
func (c *vaultClient) handleTokenRenewal(ctx context.Context) {
	if err := c.RenewToken(ctx); err != nil {
		c.logger.Error("failed to renew token", observability.Error(err))
		c.handleTokenRenewalError(ctx)
	}
}

// handleTokenRenewalError handles token renewal errors.
func (c *vaultClient) handleTokenRenewalError(ctx context.Context) {
	if !c.isTokenExpired() {
		return
	}

	c.logger.Info("token expired, attempting re-authentication")
	if err := c.reauthenticate(ctx); err != nil {
		c.logger.Error("failed to re-authenticate", observability.Error(err))
	}
}

// updateRenewalInterval updates the renewal interval if TTL has changed.
func (c *vaultClient) updateRenewalInterval(ticker *time.Ticker, currentInterval time.Duration) time.Duration {
	newInterval := c.calculateRenewalInterval()
	if newInterval <= 0 || newInterval == currentInterval {
		return currentInterval
	}

	ticker.Reset(newInterval)
	c.logger.Debug("updated token renewal interval",
		observability.Duration("interval", newInterval),
	)
	return newInterval
}

// isTokenExpired checks if the current token has expired.
func (c *vaultClient) isTokenExpired() bool {
	expiry := c.tokenExpiry.Load()
	if expiry == 0 {
		return false
	}
	return time.Now().Unix() >= expiry
}

// reauthenticate attempts to re-authenticate with Vault.
func (c *vaultClient) reauthenticate(ctx context.Context) error {
	switch c.config.AuthMethod {
	case AuthMethodToken:
		return c.authenticateWithToken(ctx)
	case AuthMethodKubernetes:
		return c.authenticateWithKubernetes(ctx)
	case AuthMethodAppRole:
		return c.authenticateWithAppRole(ctx)
	default:
		return NewConfigurationError("authMethod", "unsupported auth method: "+string(c.config.AuthMethod))
	}
}

// getRetryConfig returns the retry configuration.
func (c *vaultClient) getRetryConfig() *RetryConfig {
	if c.config.Retry != nil {
		return c.config.Retry
	}
	return DefaultRetryConfig()
}

// disabledClient is a client that returns ErrVaultDisabled for all operations.
type disabledClient struct{}

func (c *disabledClient) IsEnabled() bool                      { return false }
func (c *disabledClient) Authenticate(_ context.Context) error { return ErrVaultDisabled }
func (c *disabledClient) RenewToken(_ context.Context) error   { return ErrVaultDisabled }
func (c *disabledClient) Health(_ context.Context) (*HealthStatus, error) {
	return nil, ErrVaultDisabled
}
func (c *disabledClient) PKI() PKIClient         { return &disabledPKIClient{} }
func (c *disabledClient) KV() KVClient           { return &disabledKVClient{} }
func (c *disabledClient) Transit() TransitClient { return &disabledTransitClient{} }
func (c *disabledClient) Close() error           { return nil }

// Ensure implementations satisfy the interface.
var (
	_ Client = (*vaultClient)(nil)
	_ Client = (*disabledClient)(nil)
)

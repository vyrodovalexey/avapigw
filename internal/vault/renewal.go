package vault

import (
	"context"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Compile-time check to ensure TokenRenewalManager implements io.Closer.
// This allows TokenRenewalManager to be used with defer patterns and
// resource management utilities that expect io.Closer.
var _ io.Closer = (*TokenRenewalManager)(nil)

// TokenRenewalConfig holds configuration for token renewal.
type TokenRenewalConfig struct {
	// RenewalInterval is the interval at which to check and renew the token.
	RenewalInterval time.Duration

	// RenewalThreshold is the time before expiry at which to renew the token.
	// If the token expires in less than this duration, it will be renewed.
	RenewalThreshold time.Duration

	// MaxRetries is the maximum number of renewal retries.
	MaxRetries int

	// RetryInterval is the interval between renewal retries.
	RetryInterval time.Duration
}

// DefaultTokenRenewalConfig returns a TokenRenewalConfig with default values.
func DefaultTokenRenewalConfig() *TokenRenewalConfig {
	return &TokenRenewalConfig{
		RenewalInterval:  5 * time.Minute,
		RenewalThreshold: 10 * time.Minute,
		MaxRetries:       3,
		RetryInterval:    30 * time.Second,
	}
}

// TokenRenewalManager manages automatic token renewal.
type TokenRenewalManager struct {
	client  *Client
	config  *TokenRenewalConfig
	logger  *zap.Logger
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewTokenRenewalManager creates a new TokenRenewalManager.
func NewTokenRenewalManager(client *Client, config *TokenRenewalConfig, logger *zap.Logger) *TokenRenewalManager {
	if config == nil {
		config = DefaultTokenRenewalConfig()
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	return &TokenRenewalManager{
		client: client,
		config: config,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start starts the token renewal manager.
func (m *TokenRenewalManager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	m.logger.Info("Starting token renewal manager",
		zap.Duration("renewalInterval", m.config.RenewalInterval),
		zap.Duration("renewalThreshold", m.config.RenewalThreshold),
	)

	go m.renewalLoop(ctx)
}

// renewalLoop is the main renewal loop.
func (m *TokenRenewalManager) renewalLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.RenewalInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Debug("Token renewal manager context cancelled")
			return
		case <-m.stopCh:
			m.logger.Debug("Token renewal manager stopped")
			return
		case <-ticker.C:
			m.checkAndRenew(ctx)
		}
	}
}

// checkAndRenew checks if the token needs renewal and renews it if necessary.
func (m *TokenRenewalManager) checkAndRenew(ctx context.Context) {
	if !m.shouldRenewToken() {
		return
	}

	if m.attemptRenewalWithRetries(ctx) {
		return
	}

	m.attemptReauthentication(ctx)
}

// shouldRenewToken checks if the token needs renewal based on expiry threshold.
func (m *TokenRenewalManager) shouldRenewToken() bool {
	m.client.mu.RLock()
	tokenExpiry := m.client.tokenExpiry
	m.client.mu.RUnlock()

	if tokenExpiry.IsZero() {
		m.logger.Debug("Token does not expire, skipping renewal")
		return false
	}

	timeUntilExpiry := time.Until(tokenExpiry)
	if timeUntilExpiry > m.config.RenewalThreshold {
		m.logger.Debug("Token not yet due for renewal",
			zap.Duration("timeUntilExpiry", timeUntilExpiry),
			zap.Duration("threshold", m.config.RenewalThreshold),
		)
		return false
	}

	m.logger.Info("Token approaching expiry, attempting renewal",
		zap.Duration("timeUntilExpiry", timeUntilExpiry),
	)
	return true
}

// attemptRenewalWithRetries attempts to renew the token with configured retries.
// Returns true if renewal succeeded, false otherwise.
func (m *TokenRenewalManager) attemptRenewalWithRetries(ctx context.Context) bool {
	var lastErr error
	for attempt := 0; attempt <= m.config.MaxRetries; attempt++ {
		if !m.waitForRetry(ctx, attempt) {
			return false
		}

		err := m.client.RenewToken(ctx)
		if err == nil {
			m.logger.Info("Token renewed successfully")
			UpdateTokenExpiry(m.client.tokenExpiry)
			return true
		}

		lastErr = err
		m.logger.Warn("Token renewal failed",
			zap.Int("attempt", attempt+1),
			zap.Error(err),
		)
	}

	m.logger.Error("Token renewal failed after all retries",
		zap.Int("maxRetries", m.config.MaxRetries),
		zap.Error(lastErr),
	)
	return false
}

// waitForRetry waits before a retry attempt. Returns false if context is cancelled.
func (m *TokenRenewalManager) waitForRetry(ctx context.Context, attempt int) bool {
	if attempt == 0 {
		return true
	}

	m.logger.Debug("Retrying token renewal",
		zap.Int("attempt", attempt),
		zap.Int("maxRetries", m.config.MaxRetries),
	)

	select {
	case <-ctx.Done():
		return false
	case <-m.stopCh:
		return false
	case <-time.After(m.config.RetryInterval):
		return true
	}
}

// attemptReauthentication tries to re-authenticate after renewal failure.
func (m *TokenRenewalManager) attemptReauthentication(ctx context.Context) {
	m.logger.Info("Attempting re-authentication after renewal failure")
	if err := m.client.Authenticate(ctx); err != nil {
		m.logger.Error("Re-authentication failed", zap.Error(err))
	} else {
		m.logger.Info("Re-authentication successful")
		UpdateTokenExpiry(m.client.tokenExpiry)
	}
}

// Stop stops the token renewal manager.
func (m *TokenRenewalManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return
	}

	m.stopped = true
	close(m.stopCh)
	m.logger.Info("Token renewal manager stopped")
}

// Close implements io.Closer interface.
// This allows TokenRenewalManager to be used with defer patterns and
// resource management utilities that expect io.Closer.
func (m *TokenRenewalManager) Close() error {
	m.Stop()
	return nil
}

// IsStopped returns true if the manager has been stopped.
func (m *TokenRenewalManager) IsStopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopped
}

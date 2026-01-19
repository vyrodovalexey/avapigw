package vault

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Secret represents a secret retrieved from Vault.
type Secret struct {
	// Data contains the secret data.
	Data map[string]interface{}

	// Metadata contains the secret metadata (KV v2).
	Metadata *SecretMetadata

	// LeaseID is the lease ID for the secret.
	LeaseID string

	// LeaseDuration is the lease duration in seconds.
	LeaseDuration int

	// Renewable indicates if the lease is renewable.
	Renewable bool
}

// SecretMetadata contains metadata for a KV v2 secret.
type SecretMetadata struct {
	// CreatedTime is when the secret was created.
	CreatedTime time.Time

	// Version is the version of the secret.
	Version int

	// DeletedTime is when the secret was deleted (soft delete).
	DeletedTime *time.Time

	// Destroyed indicates if the secret was destroyed.
	Destroyed bool
}

// GetString returns a string value from the secret data.
func (s *Secret) GetString(key string) (string, bool) {
	if s == nil || s.Data == nil {
		return "", false
	}
	v, ok := s.Data[key]
	if !ok {
		return "", false
	}
	str, ok := v.(string)
	return str, ok
}

// GetBytes returns a byte slice value from the secret data.
func (s *Secret) GetBytes(key string) ([]byte, bool) {
	str, ok := s.GetString(key)
	if !ok {
		return nil, false
	}
	return []byte(str), true
}

// SecretCallback is called when a secret changes.
type SecretCallback func(secret *Secret, err error)

// SecretManager manages secrets with caching and watching capabilities.
type SecretManager struct {
	client   *Client
	cache    *SecretCache
	watchers map[string]*SecretWatcher
	mu       sync.RWMutex
	logger   *zap.Logger
}

// NewSecretManager creates a new SecretManager.
func NewSecretManager(client *Client, logger *zap.Logger) *SecretManager {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &SecretManager{
		client:   client,
		cache:    NewSecretCache(5 * time.Minute),
		watchers: make(map[string]*SecretWatcher),
		logger:   logger,
	}
}

// GetSecret retrieves a secret from Vault.
func (m *SecretManager) GetSecret(ctx context.Context, path string) (*Secret, error) {
	return m.client.ReadSecret(ctx, path)
}

// GetSecretWithCache retrieves a secret from cache or Vault.
func (m *SecretManager) GetSecretWithCache(ctx context.Context, path string, ttl time.Duration) (*Secret, error) {
	// Try cache first
	if secret, ok := m.cache.Get(path); ok {
		m.logger.Debug("Secret retrieved from cache", zap.String("path", path))
		return secret, nil
	}

	// Fetch from Vault
	secret, err := m.client.ReadSecret(ctx, path)
	if err != nil {
		return nil, err
	}

	// Store in cache
	m.cache.SetWithTTL(path, secret, ttl)
	m.logger.Debug("Secret cached", zap.String("path", path), zap.Duration("ttl", ttl))

	return secret, nil
}

// WatchSecret starts watching a secret for changes.
func (m *SecretManager) WatchSecret(
	ctx context.Context,
	path string,
	interval time.Duration,
	callback SecretCallback,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already watching
	if _, exists := m.watchers[path]; exists {
		m.logger.Debug("Already watching secret", zap.String("path", path))
		return nil
	}

	// Create watcher
	watcher := NewSecretWatcher(path, interval, callback, m.logger)
	m.watchers[path] = watcher

	// Start watching
	go watcher.Start(ctx, m.client)

	m.logger.Info("Started watching secret", zap.String("path", path), zap.Duration("interval", interval))
	UpdateSecretsWatched(len(m.watchers))

	return nil
}

// StopWatching stops watching a secret.
func (m *SecretManager) StopWatching(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	watcher, exists := m.watchers[path]
	if !exists {
		return
	}

	watcher.Stop()
	delete(m.watchers, path)

	m.logger.Info("Stopped watching secret", zap.String("path", path))
	UpdateSecretsWatched(len(m.watchers))
}

// StopAllWatchers stops all secret watchers.
func (m *SecretManager) StopAllWatchers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for path, watcher := range m.watchers {
		watcher.Stop()
		m.logger.Debug("Stopped watcher", zap.String("path", path))
	}

	m.watchers = make(map[string]*SecretWatcher)
	UpdateSecretsWatched(0)
	m.logger.Info("Stopped all secret watchers")
}

// InvalidateCache invalidates a cached secret.
func (m *SecretManager) InvalidateCache(path string) {
	m.cache.Delete(path)
	m.logger.Debug("Invalidated cache", zap.String("path", path))
}

// ClearCache clears all cached secrets.
func (m *SecretManager) ClearCache() {
	m.cache.Clear()
	m.logger.Debug("Cleared secret cache")
}

// GetWatchedPaths returns the list of paths being watched.
func (m *SecretManager) GetWatchedPaths() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	paths := make([]string, 0, len(m.watchers))
	for path := range m.watchers {
		paths = append(paths, path)
	}
	return paths
}

// Close closes the secret manager and stops all watchers.
func (m *SecretManager) Close() error {
	m.StopAllWatchers()
	m.ClearCache()
	return nil
}

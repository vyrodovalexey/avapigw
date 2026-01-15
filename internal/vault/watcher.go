package vault

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// SecretWatcher watches a secret for changes.
type SecretWatcher struct {
	path        string
	interval    time.Duration
	callback    SecretCallback
	lastVersion int
	lastHash    string
	stopCh      chan struct{}
	stopped     bool
	mu          sync.Mutex
	logger      *zap.Logger
}

// NewSecretWatcher creates a new SecretWatcher.
func NewSecretWatcher(path string, interval time.Duration, callback SecretCallback, logger *zap.Logger) *SecretWatcher {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &SecretWatcher{
		path:     path,
		interval: interval,
		callback: callback,
		stopCh:   make(chan struct{}),
		logger:   logger,
	}
}

// Start starts watching the secret.
func (w *SecretWatcher) Start(ctx context.Context, client *Client) {
	w.logger.Info("Starting secret watcher",
		zap.String("path", w.path),
		zap.Duration("interval", w.interval),
	)

	// Check for context cancellation before starting to prevent goroutine leak
	// if the context is already cancelled when Start is called.
	select {
	case <-ctx.Done():
		w.logger.Debug("Secret watcher context already cancelled before start", zap.String("path", w.path))
		return
	case <-w.stopCh:
		w.logger.Debug("Secret watcher already stopped before start", zap.String("path", w.path))
		return
	default:
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Initial fetch with context cancellation check to prevent goroutine leak
	// if context is cancelled during the initial fetch.
	select {
	case <-ctx.Done():
		w.logger.Debug("Secret watcher context cancelled before initial fetch", zap.String("path", w.path))
		return
	case <-w.stopCh:
		w.logger.Debug("Secret watcher stopped before initial fetch", zap.String("path", w.path))
		return
	default:
		w.checkSecret(ctx, client)
	}

	for {
		select {
		case <-ctx.Done():
			w.logger.Debug("Secret watcher context cancelled", zap.String("path", w.path))
			return
		case <-w.stopCh:
			w.logger.Debug("Secret watcher stopped", zap.String("path", w.path))
			return
		case <-ticker.C:
			w.checkSecret(ctx, client)
		}
	}
}

// checkSecret checks if the secret has changed.
func (w *SecretWatcher) checkSecret(ctx context.Context, client *Client) {
	w.logger.Debug("Checking secret for changes", zap.String("path", w.path))

	secret, err := client.ReadSecret(ctx, w.path)
	if err != nil {
		w.logger.Error("Failed to read secret",
			zap.String("path", w.path),
			zap.Error(err),
		)
		RecordSecretRefresh(w.path, false)
		if w.callback != nil {
			w.callback(nil, err)
		}
		return
	}

	// Check if secret has changed
	changed := false
	if secret.Metadata != nil {
		if secret.Metadata.Version != w.lastVersion {
			w.logger.Info("Secret version changed",
				zap.String("path", w.path),
				zap.Int("oldVersion", w.lastVersion),
				zap.Int("newVersion", secret.Metadata.Version),
			)
			w.lastVersion = secret.Metadata.Version
			changed = true
		}
	} else {
		// For KV v1 or other backends, compute a simple hash
		hash := computeDataHash(secret.Data)
		if hash != w.lastHash {
			w.logger.Info("Secret data changed",
				zap.String("path", w.path),
			)
			w.lastHash = hash
			changed = true
		}
	}

	RecordSecretRefresh(w.path, true)

	if changed && w.callback != nil {
		w.callback(secret, nil)
	}
}

// computeDataHash computes a simple hash of the secret data.
// Uses sorted keys for deterministic output and strings.Builder for efficient concatenation.
func computeDataHash(data map[string]interface{}) string {
	if data == nil {
		return ""
	}

	// Sort keys for deterministic output
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Use strings.Builder for efficient concatenation
	var builder strings.Builder
	builder.Grow(len(data) * 32) // Pre-allocate approximate size

	for _, k := range keys {
		if s, ok := data[k].(string); ok {
			builder.WriteString(k)
			builder.WriteByte(':')
			builder.WriteString(s)
			builder.WriteByte(';')
		}
	}
	return builder.String()
}

// Stop stops watching the secret.
func (w *SecretWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.stopped {
		return
	}

	w.stopped = true
	close(w.stopCh)
	w.logger.Info("Secret watcher stopped", zap.String("path", w.path))
}

// IsStopped returns true if the watcher has been stopped.
func (w *SecretWatcher) IsStopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

// Path returns the path being watched.
func (w *SecretWatcher) Path() string {
	return w.path
}

// Interval returns the watch interval.
func (w *SecretWatcher) Interval() time.Duration {
	return w.interval
}

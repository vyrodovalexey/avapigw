// Package config provides configuration management for the API Gateway.
package config

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.uber.org/zap"
)

var (
	// Prometheus metrics for config watcher
	configReloadTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "avapigw_config_reload_total",
			Help: "Total number of configuration reloads",
		},
		[]string{"status"},
	)

	configReloadDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "avapigw_config_reload_duration_seconds",
			Help:    "Duration of configuration reload operations",
			Buckets: prometheus.DefBuckets,
		},
	)

	configWatcherErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "avapigw_config_watcher_errors_total",
			Help: "Total number of config watcher errors",
		},
	)
)

// ConfigCallback is a function that is called when the configuration changes.
// It receives the new LocalConfig and returns an error if the config cannot be applied.
type ConfigCallback func(*LocalConfig) error

// ConfigWatcher watches a configuration file for changes and triggers reloads.
type ConfigWatcher struct {
	path     string
	watcher  *fsnotify.Watcher
	callback ConfigCallback
	debounce time.Duration
	logger   *zap.Logger

	mu           sync.RWMutex
	lastConfig   *LocalConfig
	lastModTime  time.Time
	running      bool
	stopCh       chan struct{}
	reloadCh     chan struct{}
	lastReloadAt time.Time
}

// ConfigWatcherOption is a functional option for ConfigWatcher.
type ConfigWatcherOption func(*ConfigWatcher)

// WithDebounce sets the debounce duration for the watcher.
// This prevents multiple reloads when a file is modified multiple times in quick succession.
func WithDebounce(d time.Duration) ConfigWatcherOption {
	return func(w *ConfigWatcher) {
		w.debounce = d
	}
}

// WithLogger sets the logger for the watcher.
func WithLogger(logger *zap.Logger) ConfigWatcherOption {
	return func(w *ConfigWatcher) {
		w.logger = logger
	}
}

// NewConfigWatcher creates a new ConfigWatcher for the specified file path.
// The callback function is called whenever the configuration file changes.
func NewConfigWatcher(path string, callback ConfigCallback, opts ...ConfigWatcherOption) (*ConfigWatcher, error) {
	if path == "" {
		return nil, ErrConfigPathEmpty
	}

	if callback == nil {
		return nil, ErrCallbackNil
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, &ConfigError{
			Op:   "resolve_path",
			Path: path,
			Err:  err,
		}
	}

	w := &ConfigWatcher{
		path:     absPath,
		callback: callback,
		debounce: 500 * time.Millisecond, // Default debounce
		logger:   zap.NewNop(),
		stopCh:   make(chan struct{}),
		reloadCh: make(chan struct{}, 1),
	}

	// Apply options
	for _, opt := range opts {
		opt(w)
	}

	return w, nil
}

// Start begins watching the configuration file for changes.
// It blocks until the context is cancelled or Stop is called.
func (w *ConfigWatcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return ErrWatcherAlreadyRunning
	}
	w.running = true
	w.mu.Unlock()

	// Create fsnotify watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
		return &ConfigError{
			Op:   "create_watcher",
			Path: w.path,
			Err:  err,
		}
	}
	w.watcher = watcher

	// Watch the directory containing the config file
	// This is necessary because some editors (like vim) create a new file
	// and rename it, which doesn't trigger a WRITE event on the original file
	dir := filepath.Dir(w.path)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
		return &ConfigError{
			Op:   "watch_directory",
			Path: dir,
			Err:  err,
		}
	}

	w.logger.Info("config watcher started",
		zap.String("path", w.path),
		zap.String("directory", dir),
		zap.Duration("debounce", w.debounce),
	)

	// Load initial configuration
	if err := w.reload(); err != nil {
		w.logger.Warn("failed to load initial configuration",
			zap.String("path", w.path),
			zap.Error(err),
		)
	}

	// Start watching
	go w.watch(ctx)

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
		w.logger.Info("config watcher stopping due to context cancellation")
	case <-w.stopCh:
		w.logger.Info("config watcher stopping due to stop signal")
	}

	return w.cleanup()
}

// Stop stops the configuration watcher.
func (w *ConfigWatcher) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return nil
	}

	close(w.stopCh)
	return nil
}

// ForceReload triggers an immediate reload of the configuration file.
func (w *ConfigWatcher) ForceReload() error {
	return w.reload()
}

// GetLastConfig returns the last successfully loaded configuration.
func (w *ConfigWatcher) GetLastConfig() *LocalConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastConfig
}

// GetLastReloadTime returns the time of the last successful reload.
func (w *ConfigWatcher) GetLastReloadTime() time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastReloadAt
}

// IsRunning returns true if the watcher is currently running.
func (w *ConfigWatcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// watch is the main watch loop that handles file system events.
func (w *ConfigWatcher) watch(ctx context.Context) {
	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	filename := filepath.Base(w.path)

	// Get a local reference to the watcher channels to avoid race conditions
	// The watcher is set before this goroutine starts and only cleared after it exits
	w.mu.RLock()
	watcher := w.watcher
	w.mu.RUnlock()

	if watcher == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}

			// Only process events for our config file
			if filepath.Base(event.Name) != filename {
				continue
			}

			w.logger.Debug("received file system event",
				zap.String("name", event.Name),
				zap.String("op", event.Op.String()),
			)

			// Handle relevant events
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				// Reset debounce timer
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.NewTimer(w.debounce)
				debounceCh = debounceTimer.C
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			w.logger.Error("watcher error",
				zap.Error(err),
			)
			configWatcherErrors.Inc()

		case <-debounceCh:
			// Debounce timer expired, reload configuration
			w.logger.Info("reloading configuration after debounce",
				zap.String("path", w.path),
			)
			if err := w.reload(); err != nil {
				w.logger.Error("failed to reload configuration",
					zap.String("path", w.path),
					zap.Error(err),
				)
			}
			debounceCh = nil
		}
	}
}

// reload loads and validates the configuration file, then calls the callback.
func (w *ConfigWatcher) reload() error {
	start := time.Now()

	w.logger.Debug("loading configuration",
		zap.String("path", w.path),
	)

	// Load configuration
	cfg, err := LoadAndValidateYAMLConfig(w.path)
	if err != nil {
		configReloadTotal.WithLabelValues("error").Inc()
		return &ConfigError{
			Op:   "load_config",
			Path: w.path,
			Err:  err,
		}
	}

	// Call the callback
	if err := w.callback(cfg); err != nil {
		configReloadTotal.WithLabelValues("callback_error").Inc()
		return &ConfigError{
			Op:   "apply_config",
			Path: w.path,
			Err:  err,
		}
	}

	// Update state
	w.mu.Lock()
	w.lastConfig = cfg
	w.lastReloadAt = time.Now()
	w.mu.Unlock()

	duration := time.Since(start)
	configReloadDuration.Observe(duration.Seconds())
	configReloadTotal.WithLabelValues("success").Inc()

	w.logger.Info("configuration reloaded successfully",
		zap.String("path", w.path),
		zap.Duration("duration", duration),
	)

	return nil
}

// cleanup cleans up resources when the watcher stops.
func (w *ConfigWatcher) cleanup() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.running = false

	if w.watcher != nil {
		if err := w.watcher.Close(); err != nil {
			return &ConfigError{
				Op:   "close_watcher",
				Path: w.path,
				Err:  err,
			}
		}
		w.watcher = nil
	}

	w.logger.Info("config watcher stopped",
		zap.String("path", w.path),
	)

	return nil
}

// ConfigError represents an error that occurred during configuration operations.
type ConfigError struct {
	Op   string
	Path string
	Err  error
}

func (e *ConfigError) Error() string {
	if e.Path != "" {
		return "config " + e.Op + " " + e.Path + ": " + e.Err.Error()
	}
	return "config " + e.Op + ": " + e.Err.Error()
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// Sentinel errors for config watcher.
var (
	ErrConfigPathEmpty       = &ConfigError{Op: "validate", Err: errConfigPathEmpty}
	ErrCallbackNil           = &ConfigError{Op: "validate", Err: errCallbackNil}
	ErrWatcherAlreadyRunning = &ConfigError{Op: "start", Err: errWatcherAlreadyRunning}
)

var (
	errConfigPathEmpty       = stringError("config path is empty")
	errCallbackNil           = stringError("callback is nil")
	errWatcherAlreadyRunning = stringError("watcher is already running")
)

type stringError string

func (e stringError) Error() string {
	return string(e)
}

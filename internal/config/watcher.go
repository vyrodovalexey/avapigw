package config

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ConfigCallback is called when configuration changes.
type ConfigCallback func(*GatewayConfig)

// ErrorCallback is called when an error occurs during config reload.
type ErrorCallback func(error)

// PreValidateTransform normalizes a freshly parsed configuration BEFORE the
// watcher validates it and returns the effective configuration to validate,
// store, and deliver to the reload callback. Callers use it to apply the
// same normalization performed at boot (e.g. the cmd/gateway Vault
// environment overlay), so a file that is only valid together with
// environment-supplied values does not fail raw-file validation and kill hot
// reload. The watcher always hands the hook a defensive shallow copy of the
// raw parsed configuration; hooks may replace top-level sections on that
// copy but must not deep-mutate shared sub-structures of the input.
type PreValidateTransform func(*GatewayConfig) *GatewayConfig

// Watcher watches configuration files for changes and triggers reloads.
type Watcher struct {
	path                 string
	watcher              *fsnotify.Watcher
	callback             ConfigCallback
	errorCallback        ErrorCallback
	preValidateTransform PreValidateTransform
	logger               observability.Logger
	debounceDelay        time.Duration
	lastConfig           *GatewayConfig
	mu                   sync.RWMutex
	stopCh               chan struct{}
	stoppedCh            chan struct{}
	running              bool
}

// WatcherOption is a functional option for configuring the watcher.
type WatcherOption func(*Watcher)

// WithDebounceDelay sets the debounce delay for file changes.
func WithDebounceDelay(delay time.Duration) WatcherOption {
	return func(w *Watcher) {
		w.debounceDelay = delay
	}
}

// WithLogger sets the logger for the watcher.
func WithLogger(logger observability.Logger) WatcherOption {
	return func(w *Watcher) {
		w.logger = logger
	}
}

// WithErrorCallback sets the error callback for the watcher.
func WithErrorCallback(callback ErrorCallback) WatcherOption {
	return func(w *Watcher) {
		w.errorCallback = callback
	}
}

// WithPreValidateTransform sets a transform hook applied to every freshly
// loaded configuration BEFORE validation (initial Start load, watch-loop
// reloads, and ForceReload). The transformed configuration is what gets
// validated, stored as the last config, and passed to the reload callback.
// When no hook is set, the watcher behavior is unchanged: the raw parsed
// configuration is validated and delivered as-is.
func WithPreValidateTransform(transform PreValidateTransform) WatcherOption {
	return func(w *Watcher) {
		w.preValidateTransform = transform
	}
}

// NewWatcher creates a new configuration watcher.
func NewWatcher(path string, callback ConfigCallback, opts ...WatcherOption) (*Watcher, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		path:          absPath,
		watcher:       fsWatcher,
		callback:      callback,
		debounceDelay: DefaultWatcherDebounceDelay,
		logger:        observability.NopLogger(),
		stopCh:        make(chan struct{}),
		stoppedCh:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(w)
	}

	return w, nil
}

// Start begins watching the configuration file.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	// Load initial configuration
	config, err := LoadConfig(w.path)
	if err != nil {
		return err
	}

	config = w.effectiveConfig(config)

	if err := ValidateConfig(config); err != nil {
		return err
	}

	w.mu.Lock()
	w.lastConfig = config
	w.mu.Unlock()

	// Add the file and its directory to the watcher
	dir := filepath.Dir(w.path)
	if err := w.watcher.Add(dir); err != nil {
		return err
	}

	w.logger.Info("started watching configuration file",
		observability.String("path", w.path),
	)

	go w.watch(ctx)

	return nil
}

// Stop stops watching the configuration file.
func (w *Watcher) Stop() error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	<-w.stoppedCh

	return w.watcher.Close()
}

// GetLastConfig returns the last successfully loaded configuration.
func (w *Watcher) GetLastConfig() *GatewayConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.lastConfig
}

// effectiveConfig applies the pre-validate transform hook to a freshly
// parsed configuration and returns the effective configuration to validate
// and deliver. Without a hook the raw configuration is returned unchanged
// (identity — byte-identical legacy behavior). With a hook, a defensive
// shallow copy is handed to the hook so implementations that assign
// top-level sections in place (e.g. cfg.Spec.Vault = overlay(...)) can never
// mutate the raw parsed configuration the watcher loaded.
func (w *Watcher) effectiveConfig(raw *GatewayConfig) *GatewayConfig {
	if w.preValidateTransform == nil {
		return raw
	}

	// Shallow copy: Spec is a value, so replacing pointer sections on the
	// copy leaves the raw configuration untouched.
	cp := *raw
	if effective := w.preValidateTransform(&cp); effective != nil {
		return effective
	}

	// Defensive: a hook that (incorrectly) returns nil falls back to the
	// copy it received, which carries any in-place transformations.
	return &cp
}

// watch is the main watch loop.
func (w *Watcher) watch(ctx context.Context) {
	defer close(w.stoppedCh)

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	// Ensure debounce timer is cleaned up on exit to prevent goroutine leak
	defer func() {
		if debounceTimer != nil {
			debounceTimer.Stop()
		}
	}()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("config watcher stopped due to context cancellation")
			return

		case <-w.stopCh:
			w.logger.Info("config watcher stopped")
			return

		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			debounceTimer, debounceCh = w.handleFileEvent(event, debounceTimer, debounceCh)

		case <-debounceCh:
			debounceCh = nil
			w.reload(ctx)

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.handleWatchError(err)
		}
	}
}

// handleFileEvent processes a file system event and returns updated debounce timer.
func (w *Watcher) handleFileEvent(
	event fsnotify.Event,
	debounceTimer *time.Timer,
	debounceCh <-chan time.Time,
) (timer *time.Timer, ch <-chan time.Time) {
	// Only process events for our config file
	if filepath.Clean(event.Name) != w.path {
		return debounceTimer, debounceCh
	}

	// Check if this is a write or create event
	if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
		return debounceTimer, debounceCh
	}

	w.logger.Debug("config file changed",
		observability.String("path", event.Name),
		observability.String("op", event.Op.String()),
	)

	// Reset debounce timer
	// Properly drain the timer channel after Stop() to prevent goroutine leak.
	// Stop() returns false if the timer has already expired or been stopped,
	// in which case we need to drain the channel to avoid blocking.
	if debounceTimer != nil {
		if !debounceTimer.Stop() {
			select {
			case <-debounceTimer.C:
			default:
			}
		}
	}
	debounceTimer = time.NewTimer(w.debounceDelay)
	return debounceTimer, debounceTimer.C
}

// handleWatchError handles watcher errors.
func (w *Watcher) handleWatchError(err error) {
	w.logger.Error("config watcher error",
		observability.Error(err),
	)
	if w.errorCallback != nil {
		w.errorCallback(err)
	}
}

// reload attempts to reload the configuration.
// It checks for context cancellation before and after expensive operations.
func (w *Watcher) reload(ctx context.Context) {
	// Check for context cancellation before starting reload
	select {
	case <-ctx.Done():
		w.logger.Debug("reload canceled before starting",
			observability.Error(ctx.Err()),
		)
		return
	default:
		// Continue with reload
	}

	w.logger.Info("reloading configuration",
		observability.String("path", w.path),
	)

	config, err := LoadConfig(w.path)
	if err != nil {
		w.logger.Error("failed to load configuration",
			observability.Error(err),
		)
		if w.errorCallback != nil {
			w.errorCallback(err)
		}
		return
	}

	// Check for context cancellation after loading config
	select {
	case <-ctx.Done():
		w.logger.Debug("reload canceled after loading config",
			observability.Error(ctx.Err()),
		)
		return
	default:
		// Continue with validation
	}

	// Validate the EFFECTIVE configuration (post transform hook) so files
	// that rely on environment-supplied values (e.g. VAULT_ADDR) do not
	// fail raw-file validation and silently disable hot reload.
	config = w.effectiveConfig(config)

	if err := ValidateConfig(config); err != nil {
		w.logger.Error("configuration validation failed",
			observability.Error(err),
		)
		if w.errorCallback != nil {
			w.errorCallback(err)
		}
		return
	}

	// Check for context cancellation after validation
	select {
	case <-ctx.Done():
		w.logger.Debug("reload canceled after validation",
			observability.Error(ctx.Err()),
		)
		return
	default:
		// Continue with applying config
	}

	w.mu.Lock()
	w.lastConfig = config
	w.mu.Unlock()

	w.logger.Info("configuration reloaded successfully")

	if w.callback != nil {
		w.callback(config)
	}
}

// ForceReload forces an immediate configuration reload.
func (w *Watcher) ForceReload() error {
	config, err := LoadConfig(w.path)
	if err != nil {
		return err
	}

	config = w.effectiveConfig(config)

	if err := ValidateConfig(config); err != nil {
		return err
	}

	w.mu.Lock()
	w.lastConfig = config
	w.mu.Unlock()

	if w.callback != nil {
		w.callback(config)
	}

	return nil
}

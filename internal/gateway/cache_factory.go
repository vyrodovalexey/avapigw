package gateway

import (
	"sync"

	"github.com/vyrodovalexey/avapigw/internal/cache"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/vault"
)

// CacheFactory manages per-route cache instances, creating them lazily
// and reusing existing ones for the same route.
type CacheFactory struct {
	caches      map[string]cache.Cache
	mu          sync.RWMutex
	logger      observability.Logger
	vaultClient vault.Client
}

// NewCacheFactory creates a new CacheFactory.
func NewCacheFactory(logger observability.Logger, vaultClient vault.Client) *CacheFactory {
	if logger == nil {
		logger = observability.NopLogger()
	}
	return &CacheFactory{
		caches:      make(map[string]cache.Cache),
		logger:      logger,
		vaultClient: vaultClient,
	}
}

// GetOrCreate returns an existing cache for the given route or creates a
// new one from the provided configuration. The cache is keyed by routeName
// so that each route gets its own isolated cache namespace.
func (f *CacheFactory) GetOrCreate(routeName string, cfg *config.CacheConfig) (cache.Cache, error) {
	f.mu.RLock()
	if c, ok := f.caches[routeName]; ok {
		f.mu.RUnlock()
		return c, nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	// Double-check after acquiring write lock
	if c, ok := f.caches[routeName]; ok {
		return c, nil
	}

	var opts []cache.CacheOption
	if f.vaultClient != nil {
		opts = append(opts, cache.WithVaultClient(f.vaultClient))
	}

	c, err := cache.New(cfg, f.logger, opts...)
	if err != nil {
		return nil, err
	}

	f.caches[routeName] = c
	f.logger.Debug("created cache for route",
		observability.String("route", routeName),
		observability.String("type", cfg.Type),
	)

	return c, nil
}

// Close closes all managed cache instances and releases resources.
func (f *CacheFactory) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var firstErr error
	for name, c := range f.caches {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
			f.logger.Warn("failed to close cache",
				observability.String("route", name),
				observability.Error(err),
			)
		}
	}
	f.caches = make(map[string]cache.Cache)
	return firstErr
}

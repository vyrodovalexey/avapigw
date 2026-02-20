// Package cache provides caching capabilities for the API Gateway.
//
// The cache package implements in-memory caching and Redis-based distributed caching
// for API responses. It supports:
//
//   - In-memory LRU cache with configurable size
//   - Redis-based distributed cache with Sentinel support
//   - Configurable TTL per entry with jitter
//   - Cache key generation based on request attributes
//   - Stale-while-revalidate support
//   - Negative caching for error responses
//   - Centralized retry logic with exponential backoff
//   - OpenTelemetry tracing for cache operations
//   - Comprehensive Prometheus metrics
//
// # Example Usage
//
//	cfg := &config.CacheConfig{
//	    Enabled:    true,
//	    Type:       "memory",
//	    TTL:        config.Duration(5 * time.Minute),
//	    MaxEntries: 10000,
//	}
//
//	cache, err := cache.New(cfg, logger)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer cache.Close()
//
//	// Store a value
//	err = cache.Set(ctx, "key", []byte("value"), 5*time.Minute)
//
//	// Retrieve a value
//	value, err := cache.Get(ctx, "key")
//
// # Thread Safety
//
// All cache implementations are safe for concurrent use.
package cache

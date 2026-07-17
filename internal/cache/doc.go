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
//   - Centralized retry logic with exponential backoff; only transient
//     errors are retried (network timeouts, refused/reset connections,
//     Redis LOADING/READONLY failover states) while permanent server
//     replies (WRONGTYPE, OOM, NOAUTH, MOVED, ...) fail fast
//   - OpenTelemetry tracing for cache operations; when key hashing is
//     enabled, span attributes and logs record the hashed key only
//   - Comprehensive Prometheus metrics (duration, errors, hits/misses)
//     for all Redis operations including GetWithTTL, SetNX and Expire
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

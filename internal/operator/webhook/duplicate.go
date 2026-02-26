// Package webhook provides admission webhooks for the operator.
package webhook

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"sigs.k8s.io/controller-runtime/pkg/client"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/operator/keys"
)

// DuplicateCheckerConfig holds configuration for creating a DuplicateChecker.
type DuplicateCheckerConfig struct {
	// ClusterWide enables cluster-wide duplicate detection.
	// When false (default), duplicate detection is namespace-scoped for better performance.
	ClusterWide bool

	// CacheEnabled enables caching of existing resources for efficient lookup.
	CacheEnabled bool

	// CacheTTL is the TTL for cache entries.
	CacheTTL time.Duration
}

// DefaultDuplicateCheckerConfig returns the default configuration for DuplicateChecker.
func DefaultDuplicateCheckerConfig() DuplicateCheckerConfig {
	return DuplicateCheckerConfig{
		ClusterWide:  false,
		CacheEnabled: true,
		CacheTTL:     defaultCacheTTL,
	}
}

// duplicateMetrics holds Prometheus metrics for duplicate detection.
type duplicateMetrics struct {
	checkDuration *prometheus.HistogramVec
	checkTotal    *prometheus.CounterVec
	cacheHits     *prometheus.CounterVec
	cacheMisses   *prometheus.CounterVec
}

var (
	duplicateMetricsInstance *duplicateMetrics
	duplicateMetricsOnce     sync.Once
)

// InitDuplicateMetrics initializes the singleton duplicate detection metrics instance
// with the given Prometheus registerer. If registerer is nil, metrics are registered
// with the default registerer. Must be called before getDuplicateMetrics for metrics
// to appear on the correct registry; subsequent calls are no-ops (sync.Once).
func InitDuplicateMetrics(registerer prometheus.Registerer) {
	duplicateMetricsOnce.Do(func() {
		if registerer == nil {
			registerer = prometheus.DefaultRegisterer
		}
		duplicateMetricsInstance = newDuplicateMetricsWithFactory(promauto.With(registerer))
	})
}

// getDuplicateMetrics returns the singleton duplicate detection metrics instance.
// If InitDuplicateMetrics has not been called, metrics are lazily
// initialized with the default registerer.
func getDuplicateMetrics() *duplicateMetrics {
	InitDuplicateMetrics(nil)
	return duplicateMetricsInstance
}

// newDuplicateMetricsWithFactory creates duplicate detection metrics using the given promauto factory.
func newDuplicateMetricsWithFactory(factory promauto.Factory) *duplicateMetrics {
	return &duplicateMetrics{
		checkDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "duplicate_check_duration_seconds",
				Help:      "Duration of duplicate check operations in seconds",
				Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
			},
			[]string{"resource_type", "scope"},
		),
		checkTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "duplicate_check_total",
				Help:      "Total number of duplicate check operations",
			},
			[]string{"resource_type", "scope", "result"},
		),
		cacheHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "duplicate_cache_hits_total",
				Help:      "Total number of duplicate check cache hits",
			},
			[]string{"resource_type"},
		),
		cacheMisses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "avapigw_operator",
				Subsystem: "webhook",
				Name:      "duplicate_cache_misses_total",
				Help:      "Total number of duplicate check cache misses",
			},
			[]string{"resource_type"},
		),
	}
}

// InitDuplicateVecMetrics pre-populates all duplicateMetrics vector metrics with common
// label combinations so they appear on /metrics immediately with zero values.
func InitDuplicateVecMetrics() {
	m := getDuplicateMetrics()

	resourceTypes := []string{"apiroute", "grpcroute", "graphqlroute", "backend", "grpcbackend", "graphqlbackend"}
	scopes := []string{"namespace", "cluster"}
	results := []string{"ok", "conflict", "error"}

	for _, rt := range resourceTypes {
		for _, s := range scopes {
			// checkTotal: resource_type × scope × result
			for _, r := range results {
				m.checkTotal.WithLabelValues(rt, s, r)
			}
			// checkDuration: resource_type × scope
			m.checkDuration.WithLabelValues(rt, s)
		}
		// cacheHits: resource_type
		m.cacheHits.WithLabelValues(rt)
		// cacheMisses: resource_type
		m.cacheMisses.WithLabelValues(rt)
	}
}

// DuplicateCheckerOption is a functional option for configuring DuplicateChecker.
type DuplicateCheckerOption func(*DuplicateChecker)

// WithNamespaceScoped configures the DuplicateChecker to only check for duplicates
// within the same namespace. This improves performance by reducing the scope of
// the duplicate check and is the recommended setting for most deployments.
func WithNamespaceScoped(namespaceScoped bool) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.namespaceScoped.Store(namespaceScoped)
	}
}

// WithCacheEnabled enables caching of existing resources for efficient lookup.
func WithCacheEnabled(enabled bool) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.cacheEnabled = enabled
	}
}

// WithCacheTTL sets the cache TTL duration.
func WithCacheTTL(ttl time.Duration) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.cacheTTL = ttl
	}
}

// WithCleanupInterval sets the interval for automatic cache cleanup.
// The cleanup goroutine removes entries older than 2x TTL.
func WithCleanupInterval(interval time.Duration) DuplicateCheckerOption {
	return func(dc *DuplicateChecker) {
		dc.cleanupInterval = interval
	}
}

// DuplicateDetectionScope defines the scope for duplicate detection.
type DuplicateDetectionScope string

const (
	// ScopeNamespace checks for duplicates within the same namespace only.
	ScopeNamespace DuplicateDetectionScope = "namespace"

	// ScopeCluster checks for duplicates across all namespaces.
	ScopeCluster DuplicateDetectionScope = "cluster"
)

// Default cache configuration.
const (
	// defaultCacheTTL is the default time-to-live for cached entries.
	defaultCacheTTL = 30 * time.Second

	// defaultCleanupInterval is the default interval for cache cleanup.
	defaultCleanupInterval = 1 * time.Minute

	// cacheExpirationMultiplier determines when entries are considered stale (TTL * multiplier).
	cacheExpirationMultiplier = 2
)

// resourceCache holds cached resources for efficient duplicate detection.
type resourceCache struct {
	mu              sync.RWMutex
	apiRoutes       map[string]*avapigwv1alpha1.APIRouteList
	grpcRoutes      map[string]*avapigwv1alpha1.GRPCRouteList
	graphqlRoutes   map[string]*avapigwv1alpha1.GraphQLRouteList
	backends        map[string]*avapigwv1alpha1.BackendList
	grpcBackends    map[string]*avapigwv1alpha1.GRPCBackendList
	graphqlBackends map[string]*avapigwv1alpha1.GraphQLBackendList
	lastRefresh     map[string]time.Time
}

// newResourceCache creates a new resource cache.
func newResourceCache() *resourceCache {
	return &resourceCache{
		apiRoutes:       make(map[string]*avapigwv1alpha1.APIRouteList),
		grpcRoutes:      make(map[string]*avapigwv1alpha1.GRPCRouteList),
		graphqlRoutes:   make(map[string]*avapigwv1alpha1.GraphQLRouteList),
		backends:        make(map[string]*avapigwv1alpha1.BackendList),
		grpcBackends:    make(map[string]*avapigwv1alpha1.GRPCBackendList),
		graphqlBackends: make(map[string]*avapigwv1alpha1.GraphQLBackendList),
		lastRefresh:     make(map[string]time.Time),
	}
}

// DuplicateChecker checks for duplicate resources across the cluster or within a namespace.
type DuplicateChecker struct {
	client          client.Client
	logger          observability.Logger
	namespaceScoped atomic.Bool // If true, only check for duplicates within the same namespace
	cacheEnabled    bool
	cacheTTL        time.Duration
	cleanupInterval time.Duration
	cache           *resourceCache

	// Cleanup goroutine lifecycle
	stopCleanup chan struct{}
	cleanupDone chan struct{}
	stopOnce    sync.Once
}

// NewDuplicateChecker creates a new DuplicateChecker with a background context.
// By default, it checks for duplicates within the same namespace only (namespace-scoped).
// Use WithNamespaceScoped(false) to check across all namespaces.
// When caching is enabled, a background cleanup goroutine is started automatically.
// Call Stop() to gracefully shutdown the cleanup goroutine.
//
// Deprecated: Use NewDuplicateCheckerWithContext for proper lifecycle management.
func NewDuplicateChecker(c client.Client, opts ...DuplicateCheckerOption) *DuplicateChecker {
	return NewDuplicateCheckerWithContext(context.Background(), c, opts...)
}

// NewDuplicateCheckerWithContext creates a new DuplicateChecker with context-based cancellation.
// The cleanup goroutine will stop when the context is canceled or when Stop() is called.
// By default, it checks for duplicates within the same namespace only (namespace-scoped).
// Use WithNamespaceScoped(false) to check across all namespaces.
func NewDuplicateCheckerWithContext(
	ctx context.Context,
	c client.Client,
	opts ...DuplicateCheckerOption,
) *DuplicateChecker {
	dc := &DuplicateChecker{
		client:          c,
		cacheEnabled:    false,
		cacheTTL:        defaultCacheTTL,
		cleanupInterval: defaultCleanupInterval,
		cache:           newResourceCache(),
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
		logger: observability.GetGlobalLogger().With(
			observability.String("component", "duplicate-checker"),
		),
	}
	dc.namespaceScoped.Store(true) // Default to namespace-scoped for better performance

	for _, opt := range opts {
		opt(dc)
	}

	// Start background cleanup goroutine if caching is enabled
	if dc.cacheEnabled {
		go dc.runCleanupLoopWithContext(ctx)
	}

	return dc
}

// NewDuplicateCheckerFromConfig creates a new DuplicateChecker from a configuration struct.
// This is the preferred way to create a DuplicateChecker with explicit configuration.
func NewDuplicateCheckerFromConfig(c client.Client, cfg DuplicateCheckerConfig) *DuplicateChecker {
	return NewDuplicateCheckerFromConfigWithContext(context.Background(), c, cfg)
}

// NewDuplicateCheckerFromConfigWithContext creates a new DuplicateChecker from a configuration struct
// with context-based cancellation for the cleanup goroutine.
func NewDuplicateCheckerFromConfigWithContext(
	ctx context.Context,
	c client.Client,
	cfg DuplicateCheckerConfig,
) *DuplicateChecker {
	opts := []DuplicateCheckerOption{
		WithNamespaceScoped(!cfg.ClusterWide),
		WithCacheEnabled(cfg.CacheEnabled),
	}

	if cfg.CacheTTL > 0 {
		opts = append(opts, WithCacheTTL(cfg.CacheTTL))
	}

	return NewDuplicateCheckerWithContext(ctx, c, opts...)
}

// GetScope returns the current duplicate detection scope.
func (c *DuplicateChecker) GetScope() DuplicateDetectionScope {
	if c.namespaceScoped.Load() {
		return ScopeNamespace
	}
	return ScopeCluster
}

// SetScope sets the duplicate detection scope.
func (c *DuplicateChecker) SetScope(scope DuplicateDetectionScope) {
	c.namespaceScoped.Store(scope == ScopeNamespace)
}

// isCacheValidLocked checks if the cache for a given key is still valid.
// The caller MUST hold cache.mu.RLock (or cache.mu.Lock) before calling.
// This avoids the TOCTOU race between checking validity and reading cached data.
func (c *DuplicateChecker) isCacheValidLocked(cacheKey string) bool {
	lastRefresh, ok := c.cache.lastRefresh[cacheKey]
	if !ok {
		return false
	}

	return time.Since(lastRefresh) < c.cacheTTL
}

// updateCacheTimestamp updates the cache timestamp for a given key.
func (c *DuplicateChecker) updateCacheTimestamp(cacheKey string) {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	c.cache.lastRefresh[cacheKey] = time.Now()
}

// InvalidateCache invalidates all cached data.
func (c *DuplicateChecker) InvalidateCache() {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()

	c.cache.apiRoutes = make(map[string]*avapigwv1alpha1.APIRouteList)
	c.cache.grpcRoutes = make(map[string]*avapigwv1alpha1.GRPCRouteList)
	c.cache.graphqlRoutes = make(map[string]*avapigwv1alpha1.GraphQLRouteList)
	c.cache.backends = make(map[string]*avapigwv1alpha1.BackendList)
	c.cache.grpcBackends = make(map[string]*avapigwv1alpha1.GRPCBackendList)
	c.cache.graphqlBackends = make(map[string]*avapigwv1alpha1.GraphQLBackendList)
	c.cache.lastRefresh = make(map[string]time.Time)
}

// Stop gracefully shuts down the cache cleanup goroutine.
// This method is safe to call multiple times.
func (c *DuplicateChecker) Stop() {
	if !c.cacheEnabled {
		return
	}

	c.stopOnce.Do(func() {
		close(c.stopCleanup)
		<-c.cleanupDone
		c.logger.Info("duplicate checker cache cleanup stopped")
	})
}

// runCleanupLoopWithContext runs the background cache cleanup loop with context support.
// It periodically removes cache entries older than 2x TTL.
// The loop stops when the context is canceled or Stop() is called.
func (c *DuplicateChecker) runCleanupLoopWithContext(ctx context.Context) {
	defer close(c.cleanupDone)

	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	c.logger.Info("starting cache cleanup loop",
		observability.Duration("interval", c.cleanupInterval),
		observability.Duration("ttl", c.cacheTTL),
	)

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("cache cleanup loop stopping due to context cancellation")
			return
		case <-c.stopCleanup:
			c.logger.Debug("cache cleanup loop stopping")
			return
		case <-ticker.C:
			c.cleanupExpiredEntries()
		}
	}
}

// cleanupExpiredEntries removes cache entries older than 2x TTL.
func (c *DuplicateChecker) cleanupExpiredEntries() {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()

	expirationThreshold := c.cacheTTL * cacheExpirationMultiplier
	now := time.Now()
	cleanedCount := 0

	for key, lastRefresh := range c.cache.lastRefresh {
		if now.Sub(lastRefresh) <= expirationThreshold {
			continue
		}
		// Remove from all cache maps
		delete(c.cache.apiRoutes, key)
		delete(c.cache.grpcRoutes, key)
		delete(c.cache.graphqlRoutes, key)
		delete(c.cache.backends, key)
		delete(c.cache.grpcBackends, key)
		delete(c.cache.graphqlBackends, key)
		delete(c.cache.lastRefresh, key)
		cleanedCount++
	}

	if cleanedCount > 0 {
		c.logger.Debug("cleaned expired cache entries",
			observability.Int("count", cleanedCount),
		)
	}
}

// CheckAPIRouteDuplicate checks if an APIRoute with the same route match exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckAPIRouteDuplicate(
	ctx context.Context,
	route *avapigwv1alpha1.APIRoute,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "apiroute"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey(resourceType, route.Namespace)
	var routes *avapigwv1alpha1.APIRouteList

	// Try to use cached data under a single RLock to avoid TOCTOU race
	// between validity check and data read.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			routes = c.cache.apiRoutes[cacheKey]
		}
		c.cache.mu.RUnlock()
		if routes != nil {
			dm.cacheHits.WithLabelValues(resourceType).Inc()
		}
	}

	// Fetch from API if cache miss or invalid
	if routes == nil {
		dm.cacheMisses.WithLabelValues(resourceType).Inc()
		routes = &avapigwv1alpha1.APIRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(route.Namespace))
		}
		if err := c.client.List(ctx, routes, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list APIRoutes: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.apiRoutes[cacheKey] = routes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on route match criteria
	var conflicts []string
	for i := range routes.Items {
		existing := &routes.Items[i]
		// Skip self
		if existing.Namespace == route.Namespace && existing.Name == route.Name {
			continue
		}

		// Check for overlapping routes
		if c.routesOverlap(route, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("duplicate APIRoute detected",
			observability.String("new_route", keys.ResourceKey(route.Namespace, route.Name)),
			observability.Any("conflicting_routes", conflicts),
		)
		return fmt.Errorf(
			"APIRoute %s/%s conflicts with existing route(s) %s: overlapping path/method combination",
			route.Namespace, route.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// buildCacheKey builds a cache key for the given resource type and namespace.
func (c *DuplicateChecker) buildCacheKey(resourceType, namespace string) string {
	if c.namespaceScoped.Load() {
		return fmt.Sprintf("%s/%s", resourceType, namespace)
	}
	return fmt.Sprintf("%s/cluster", resourceType)
}

// getScopeLabel returns the scope label for metrics.
func (c *DuplicateChecker) getScopeLabel() string {
	if c.namespaceScoped.Load() {
		return "namespace"
	}
	return "cluster"
}

// CheckBackendDuplicate checks if a Backend with the same host:port combination exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckBackendDuplicate(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "backend"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey(resourceType, backend.Namespace)
	var backends *avapigwv1alpha1.BackendList

	// Try to use cached data under a single RLock to avoid TOCTOU race
	// between validity check and data read.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			backends = c.cache.backends[cacheKey]
		}
		c.cache.mu.RUnlock()
		if backends != nil {
			dm.cacheHits.WithLabelValues(resourceType).Inc()
		}
	}

	// Fetch from API if cache miss or invalid
	if backends == nil {
		dm.cacheMisses.WithLabelValues(resourceType).Inc()
		backends = &avapigwv1alpha1.BackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list Backends: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.backends[cacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on host:port combination
	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		// Skip self
		if existing.Namespace == backend.Namespace && existing.Name == backend.Name {
			continue
		}

		// Check for same host:port combination
		if c.backendsConflict(backend, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("duplicate Backend detected",
			observability.String("new_backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"backend %s/%s conflicts with existing backend(s) %s: same host:port combination",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// CheckGRPCRouteDuplicate checks if a GRPCRoute with the same service/method match exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckGRPCRouteDuplicate(
	ctx context.Context,
	route *avapigwv1alpha1.GRPCRoute,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "grpcroute"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey(resourceType, route.Namespace)
	var routes *avapigwv1alpha1.GRPCRouteList

	// Try to use cached data under a single RLock to avoid TOCTOU race
	// between validity check and data read.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			routes = c.cache.grpcRoutes[cacheKey]
		}
		c.cache.mu.RUnlock()
		if routes != nil {
			dm.cacheHits.WithLabelValues(resourceType).Inc()
		}
	}

	// Fetch from API if cache miss or invalid
	if routes == nil {
		dm.cacheMisses.WithLabelValues(resourceType).Inc()
		routes = &avapigwv1alpha1.GRPCRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(route.Namespace))
		}
		if err := c.client.List(ctx, routes, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list GRPCRoutes: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.grpcRoutes[cacheKey] = routes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on service/method combination
	var conflicts []string
	for i := range routes.Items {
		existing := &routes.Items[i]
		if existing.Namespace == route.Namespace && existing.Name == route.Name {
			continue
		}

		if c.grpcRoutesOverlap(route, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("duplicate GRPCRoute detected",
			observability.String("new_route", keys.ResourceKey(route.Namespace, route.Name)),
			observability.Any("conflicting_routes", conflicts),
		)
		return fmt.Errorf(
			"GRPCRoute %s/%s conflicts with existing route(s) %s: overlapping service/method",
			route.Namespace, route.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// CheckGRPCBackendDuplicate checks if a GRPCBackend with the same host:port combination exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckGRPCBackendDuplicate(
	ctx context.Context,
	backend *avapigwv1alpha1.GRPCBackend,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "grpcbackend"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey(resourceType, backend.Namespace)
	var backends *avapigwv1alpha1.GRPCBackendList

	// Try to use cached data under a single RLock to avoid TOCTOU race
	// between validity check and data read.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			backends = c.cache.grpcBackends[cacheKey]
		}
		c.cache.mu.RUnlock()
		if backends != nil {
			dm.cacheHits.WithLabelValues(resourceType).Inc()
		}
	}

	// Fetch from API if cache miss or invalid
	if backends == nil {
		dm.cacheMisses.WithLabelValues(resourceType).Inc()
		backends = &avapigwv1alpha1.GRPCBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list GRPCBackends: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.grpcBackends[cacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on host:port combination
	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		if existing.Namespace == backend.Namespace && existing.Name == backend.Name {
			continue
		}

		if c.grpcBackendsConflict(backend, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("duplicate GRPCBackend detected",
			observability.String("new_backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		return fmt.Errorf(
			"GRPCBackend %s/%s conflicts with existing backend(s) %s: same host:port",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// routesOverlap checks if two APIRoutes have overlapping match conditions.
func (c *DuplicateChecker) routesOverlap(a, b *avapigwv1alpha1.APIRoute) bool {
	// An empty match list means "catch-all" — it matches everything.
	// If either route is a catch-all, it overlaps with any other route.
	if len(a.Spec.Match) == 0 || len(b.Spec.Match) == 0 {
		return true
	}

	// Check if any match conditions overlap
	for i := range a.Spec.Match {
		matchA := &a.Spec.Match[i]
		for j := range b.Spec.Match {
			matchB := &b.Spec.Match[j]
			if c.matchConditionsOverlap(matchA, matchB) {
				return true
			}
		}
	}
	return false
}

// matchConditionsOverlap checks if two RouteMatch conditions overlap.
//
//nolint:gocyclo // URI matching requires checking multiple conditions for exact, prefix, and regex patterns
func (c *DuplicateChecker) matchConditionsOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	if a.URI == nil || b.URI == nil {
		return false
	}

	// Check exact match overlap
	if c.exactURIsOverlap(a, b) {
		return c.methodsOverlap(a.Methods, b.Methods)
	}

	// Check prefix overlap
	if c.prefixURIsOverlap(a, b) {
		return c.methodsOverlap(a.Methods, b.Methods)
	}

	// Check exact and prefix overlap
	if c.exactAndPrefixOverlap(a, b) {
		return c.methodsOverlap(a.Methods, b.Methods)
	}

	return false
}

// exactURIsOverlap checks if two exact URIs match.
func (c *DuplicateChecker) exactURIsOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	return a.URI.Exact != "" && b.URI.Exact != "" && a.URI.Exact == b.URI.Exact
}

// prefixURIsOverlap checks if two prefix URIs overlap.
func (c *DuplicateChecker) prefixURIsOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	if a.URI.Prefix == "" || b.URI.Prefix == "" {
		return false
	}
	return strings.HasPrefix(a.URI.Prefix, b.URI.Prefix) ||
		strings.HasPrefix(b.URI.Prefix, a.URI.Prefix)
}

// exactAndPrefixOverlap checks if an exact URI overlaps with a prefix URI.
func (c *DuplicateChecker) exactAndPrefixOverlap(a, b *avapigwv1alpha1.RouteMatch) bool {
	if a.URI.Exact != "" && b.URI.Prefix != "" && strings.HasPrefix(a.URI.Exact, b.URI.Prefix) {
		return true
	}
	if b.URI.Exact != "" && a.URI.Prefix != "" && strings.HasPrefix(b.URI.Exact, a.URI.Prefix) {
		return true
	}
	return false
}

// methodsOverlap checks if two method lists overlap.
func (c *DuplicateChecker) methodsOverlap(a, b []string) bool {
	// Empty means all methods
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	for _, ma := range a {
		for _, mb := range b {
			if strings.EqualFold(ma, mb) {
				return true
			}
		}
	}
	return false
}

// backendsConflict checks if two Backends have the same host:port combination.
func (c *DuplicateChecker) backendsConflict(a, b *avapigwv1alpha1.Backend) bool {
	// Check if any hosts have the same address:port
	for _, hostA := range a.Spec.Hosts {
		for _, hostB := range b.Spec.Hosts {
			if hostA.Address == hostB.Address && hostA.Port == hostB.Port {
				return true
			}
		}
	}
	return false
}

// grpcRoutesOverlap checks if two GRPCRoutes have overlapping match conditions.
func (c *DuplicateChecker) grpcRoutesOverlap(a, b *avapigwv1alpha1.GRPCRoute) bool {
	// An empty match list means "catch-all" — it matches everything.
	// If either route is a catch-all, it overlaps with any other route.
	if len(a.Spec.Match) == 0 || len(b.Spec.Match) == 0 {
		return true
	}

	// Check if service/method combinations overlap
	for i := range a.Spec.Match {
		matchA := &a.Spec.Match[i]
		for j := range b.Spec.Match {
			matchB := &b.Spec.Match[j]
			if c.grpcMatchConditionsOverlap(matchA, matchB) {
				return true
			}
		}
	}
	return false
}

// grpcMatchConditionsOverlap checks if two GRPCRouteMatch conditions overlap.
//
//nolint:gocognit // gRPC matching requires checking multiple nested conditions for service and method patterns
func (c *DuplicateChecker) grpcMatchConditionsOverlap(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	if a.Service == nil || b.Service == nil {
		return false
	}

	// Check exact service match
	if c.exactServicesMatch(a, b) {
		return c.grpcMethodsOverlap(a, b)
	}

	// Check prefix service overlap
	if c.prefixServicesOverlap(a, b) {
		return c.grpcMethodsOverlapForPrefix(a, b)
	}

	return false
}

// exactServicesMatch checks if two services have exact match.
func (c *DuplicateChecker) exactServicesMatch(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	return a.Service.Exact != "" && b.Service.Exact != "" && a.Service.Exact == b.Service.Exact
}

// prefixServicesOverlap checks if two service prefixes overlap.
func (c *DuplicateChecker) prefixServicesOverlap(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	if a.Service.Prefix == "" || b.Service.Prefix == "" {
		return false
	}
	return strings.HasPrefix(a.Service.Prefix, b.Service.Prefix) ||
		strings.HasPrefix(b.Service.Prefix, a.Service.Prefix)
}

// grpcMethodsOverlap checks if gRPC methods overlap for exact service match.
func (c *DuplicateChecker) grpcMethodsOverlap(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	// If no method specified on either, all methods match
	if a.Method == nil || b.Method == nil {
		return true
	}

	// Check exact method match
	if a.Method.Exact != "" && b.Method.Exact != "" && a.Method.Exact == b.Method.Exact {
		return true
	}

	// Check prefix overlap for methods
	if a.Method.Prefix != "" && b.Method.Prefix != "" {
		return strings.HasPrefix(a.Method.Prefix, b.Method.Prefix) ||
			strings.HasPrefix(b.Method.Prefix, a.Method.Prefix)
	}

	return false
}

// grpcMethodsOverlapForPrefix checks if gRPC methods overlap for prefix service match.
func (c *DuplicateChecker) grpcMethodsOverlapForPrefix(
	a, b *avapigwv1alpha1.GRPCRouteMatch,
) bool {
	// If no method specified on either, all methods match
	if a.Method == nil || b.Method == nil {
		return true
	}

	// Check exact method match
	return a.Method.Exact != "" && b.Method.Exact != "" && a.Method.Exact == b.Method.Exact
}

// grpcBackendsConflict checks if two GRPCBackends have the same host:port combination.
func (c *DuplicateChecker) grpcBackendsConflict(a, b *avapigwv1alpha1.GRPCBackend) bool {
	// Check if any hosts have the same address:port
	for _, hostA := range a.Spec.Hosts {
		for _, hostB := range b.Spec.Hosts {
			if hostA.Address == hostB.Address && hostA.Port == hostB.Port {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// Cross-CRD Conflict Detection
// ============================================================================

// CheckBackendCrossConflicts checks if a Backend has host:port conflicts with existing GRPCBackends.
// This prevents two different backend types from pointing to the same upstream endpoint.
func (c *DuplicateChecker) CheckBackendCrossConflicts(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("grpcbackend", backend.Namespace)
	var grpcBackends *avapigwv1alpha1.GRPCBackendList

	// Try to use cached data under a single RLock to avoid TOCTOU race.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			grpcBackends = c.cache.grpcBackends[cacheKey]
		}
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if grpcBackends == nil {
		grpcBackends = &avapigwv1alpha1.GRPCBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, grpcBackends, listOpts...); err != nil {
			return fmt.Errorf("failed to list GRPCBackends for cross-check: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.grpcBackends[cacheKey] = grpcBackends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for host:port conflicts between Backend and GRPCBackends
	var conflicts []string
	for i := range grpcBackends.Items {
		existing := &grpcBackends.Items[i]
		if c.backendAndGRPCBackendConflict(backend.Spec.Hosts, existing.Spec.Hosts) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("cross-CRD Backend/GRPCBackend conflict detected",
			observability.String("backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_grpcbackends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"Backend %s/%s has host:port conflict with GRPCBackend(s) %s",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// CheckGRPCBackendCrossConflicts checks if a GRPCBackend has host:port conflicts with existing Backends.
// This prevents two different backend types from pointing to the same upstream endpoint.
func (c *DuplicateChecker) CheckGRPCBackendCrossConflicts(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("backend", grpcBackend.Namespace)
	var backends *avapigwv1alpha1.BackendList

	// Try to use cached data under a single RLock to avoid TOCTOU race.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			backends = c.cache.backends[cacheKey]
		}
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if backends == nil {
		backends = &avapigwv1alpha1.BackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(grpcBackend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			return fmt.Errorf("failed to list Backends for cross-check: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.backends[cacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for host:port conflicts between GRPCBackend and Backends
	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		if c.backendAndGRPCBackendConflict(existing.Spec.Hosts, grpcBackend.Spec.Hosts) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("cross-CRD GRPCBackend/Backend conflict detected",
			observability.String("grpcbackend", keys.ResourceKey(grpcBackend.Namespace, grpcBackend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"GRPCBackend %s/%s has host:port conflict with Backend(s) %s",
			grpcBackend.Namespace, grpcBackend.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// backendAndGRPCBackendConflict checks if Backend hosts and GRPCBackend hosts share
// the same address:port combination.
func (c *DuplicateChecker) backendAndGRPCBackendConflict(
	backendHosts, grpcBackendHosts []avapigwv1alpha1.BackendHost,
) bool {
	for _, hostA := range backendHosts {
		for _, hostB := range grpcBackendHosts {
			if hostA.Address == hostB.Address && hostA.Port == hostB.Port {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// GraphQL Duplicate Detection
// ============================================================================

// CheckGraphQLRouteDuplicate checks if a GraphQLRoute with the same path/operation match exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckGraphQLRouteDuplicate(
	ctx context.Context,
	route *avapigwv1alpha1.GraphQLRoute,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "graphqlroute"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey(resourceType, route.Namespace)
	var routes *avapigwv1alpha1.GraphQLRouteList

	// Try to use cached data under a single RLock to avoid TOCTOU race
	// between validity check and data read.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			routes = c.cache.graphqlRoutes[cacheKey]
		}
		c.cache.mu.RUnlock()
		if routes != nil {
			dm.cacheHits.WithLabelValues(resourceType).Inc()
		}
	}

	// Fetch from API if cache miss or invalid
	if routes == nil {
		dm.cacheMisses.WithLabelValues(resourceType).Inc()
		routes = &avapigwv1alpha1.GraphQLRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(route.Namespace))
		}
		if err := c.client.List(ctx, routes, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list GraphQLRoutes: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.graphqlRoutes[cacheKey] = routes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on path/operation combination
	var conflicts []string
	for i := range routes.Items {
		existing := &routes.Items[i]
		if existing.Namespace == route.Namespace && existing.Name == route.Name {
			continue
		}

		if c.graphqlRoutesOverlap(route, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("duplicate GraphQLRoute detected",
			observability.String("new_route", keys.ResourceKey(route.Namespace, route.Name)),
			observability.Any("conflicting_routes", conflicts),
		)
		return fmt.Errorf(
			"GraphQLRoute %s/%s conflicts with existing route(s) %s: overlapping path/operation",
			route.Namespace, route.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// CheckGraphQLBackendDuplicate checks if a GraphQLBackend with the same host:port combination exists.
// If namespaceScoped is true, only checks within the same namespace for better performance.
func (c *DuplicateChecker) CheckGraphQLBackendDuplicate(
	ctx context.Context,
	backend *avapigwv1alpha1.GraphQLBackend,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "graphqlbackend"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey(resourceType, backend.Namespace)
	var backends *avapigwv1alpha1.GraphQLBackendList

	// Try to use cached data under a single RLock to avoid TOCTOU race
	// between validity check and data read.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			backends = c.cache.graphqlBackends[cacheKey]
		}
		c.cache.mu.RUnlock()
		if backends != nil {
			dm.cacheHits.WithLabelValues(resourceType).Inc()
		}
	}

	// Fetch from API if cache miss or invalid
	if backends == nil {
		dm.cacheMisses.WithLabelValues(resourceType).Inc()
		backends = &avapigwv1alpha1.GraphQLBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list GraphQLBackends: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.graphqlBackends[cacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for duplicates based on host:port combination
	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		if existing.Namespace == backend.Namespace && existing.Name == backend.Name {
			continue
		}

		if c.graphqlBackendsConflict(backend, existing) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("duplicate GraphQLBackend detected",
			observability.String("new_backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		return fmt.Errorf(
			"GraphQLBackend %s/%s conflicts with existing backend(s) %s: same host:port",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// graphqlRoutesOverlap checks if two GraphQLRoutes have overlapping match conditions.
func (c *DuplicateChecker) graphqlRoutesOverlap(a, b *avapigwv1alpha1.GraphQLRoute) bool {
	// An empty match list means "catch-all" — it matches everything.
	// If either route is a catch-all, it overlaps with any other route.
	if len(a.Spec.Match) == 0 || len(b.Spec.Match) == 0 {
		return true
	}

	// Check if any match conditions overlap
	for i := range a.Spec.Match {
		matchA := &a.Spec.Match[i]
		for j := range b.Spec.Match {
			matchB := &b.Spec.Match[j]
			if c.graphqlMatchConditionsOverlap(matchA, matchB) {
				return true
			}
		}
	}
	return false
}

// graphqlMatchConditionsOverlap checks if two GraphQLRouteMatch conditions overlap.
func (c *DuplicateChecker) graphqlMatchConditionsOverlap(
	a, b *avapigwv1alpha1.GraphQLRouteMatch,
) bool {
	// Check path overlap
	if !c.graphqlPathsOverlap(a.Path, b.Path) {
		return false
	}

	// Check operation type overlap
	if a.OperationType != "" && b.OperationType != "" && a.OperationType != b.OperationType {
		return false
	}

	return true
}

// graphqlPathsOverlap checks if two GraphQL path matches overlap.
func (c *DuplicateChecker) graphqlPathsOverlap(a, b *avapigwv1alpha1.StringMatch) bool {
	// If either path is nil, it matches everything
	if a == nil || b == nil {
		return true
	}

	// Check exact match overlap
	if a.Exact != "" && b.Exact != "" {
		return a.Exact == b.Exact
	}

	// Check prefix overlap
	if a.Prefix != "" && b.Prefix != "" {
		return strings.HasPrefix(a.Prefix, b.Prefix) ||
			strings.HasPrefix(b.Prefix, a.Prefix)
	}

	// Check exact and prefix overlap
	if a.Exact != "" && b.Prefix != "" {
		return strings.HasPrefix(a.Exact, b.Prefix)
	}
	if b.Exact != "" && a.Prefix != "" {
		return strings.HasPrefix(b.Exact, a.Prefix)
	}

	return false
}

// graphqlBackendsConflict checks if two GraphQLBackends have the same host:port combination.
func (c *DuplicateChecker) graphqlBackendsConflict(a, b *avapigwv1alpha1.GraphQLBackend) bool {
	// Check if any hosts have the same address:port
	for _, hostA := range a.Spec.Hosts {
		for _, hostB := range b.Spec.Hosts {
			if hostA.Address == hostB.Address && hostA.Port == hostB.Port {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// GraphQL Cross-CRD Conflict Detection
// ============================================================================

// CheckGraphQLBackendCrossConflicts checks if a GraphQLBackend has host:port conflicts
// with existing Backends and GRPCBackends.
// This prevents different backend types from pointing to the same upstream endpoint.
func (c *DuplicateChecker) CheckGraphQLBackendCrossConflicts(
	ctx context.Context,
	graphqlBackend *avapigwv1alpha1.GraphQLBackend,
) error {
	if c.client == nil {
		return nil
	}

	var conflicts []string

	// Check against Backends
	backendConflicts, err := c.checkGraphQLBackendVsBackends(ctx, graphqlBackend)
	if err != nil {
		return err
	}
	conflicts = append(conflicts, backendConflicts...)

	// Check against GRPCBackends
	grpcConflicts, err := c.checkGraphQLBackendVsGRPCBackends(ctx, graphqlBackend)
	if err != nil {
		return err
	}
	conflicts = append(conflicts, grpcConflicts...)

	if len(conflicts) > 0 {
		c.logger.Warn("cross-CRD GraphQLBackend conflict detected",
			observability.String("graphqlbackend",
				keys.ResourceKey(graphqlBackend.Namespace, graphqlBackend.Name)),
			observability.Any("conflicting_backends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"GraphQLBackend %s/%s has host:port conflict with %s",
			graphqlBackend.Namespace, graphqlBackend.Name,
			strings.Join(conflicts, ", "))
	}

	return nil
}

// checkGraphQLBackendVsBackends checks for host:port conflicts between a GraphQLBackend
// and existing Backends.
func (c *DuplicateChecker) checkGraphQLBackendVsBackends(
	ctx context.Context,
	graphqlBackend *avapigwv1alpha1.GraphQLBackend,
) ([]string, error) {
	backendCacheKey := c.buildCacheKey("backend", graphqlBackend.Namespace)
	var backends *avapigwv1alpha1.BackendList

	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(backendCacheKey) {
			backends = c.cache.backends[backendCacheKey]
		}
		c.cache.mu.RUnlock()
	}

	if backends == nil {
		backends = &avapigwv1alpha1.BackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(graphqlBackend.Namespace))
		}
		if err := c.client.List(ctx, backends, listOpts...); err != nil {
			return nil, fmt.Errorf("failed to list Backends for cross-check: %w", err)
		}

		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.backends[backendCacheKey] = backends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(backendCacheKey)
		}
	}

	var conflicts []string
	for i := range backends.Items {
		existing := &backends.Items[i]
		if c.backendAndGRPCBackendConflict(existing.Spec.Hosts, graphqlBackend.Spec.Hosts) {
			conflicts = append(conflicts,
				"Backend:"+keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}
	return conflicts, nil
}

// checkGraphQLBackendVsGRPCBackends checks for host:port conflicts between a GraphQLBackend
// and existing GRPCBackends.
func (c *DuplicateChecker) checkGraphQLBackendVsGRPCBackends(
	ctx context.Context,
	graphqlBackend *avapigwv1alpha1.GraphQLBackend,
) ([]string, error) {
	grpcBackendCacheKey := c.buildCacheKey("grpcbackend", graphqlBackend.Namespace)
	var grpcBackends *avapigwv1alpha1.GRPCBackendList

	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(grpcBackendCacheKey) {
			grpcBackends = c.cache.grpcBackends[grpcBackendCacheKey]
		}
		c.cache.mu.RUnlock()
	}

	if grpcBackends == nil {
		grpcBackends = &avapigwv1alpha1.GRPCBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(graphqlBackend.Namespace))
		}
		if err := c.client.List(ctx, grpcBackends, listOpts...); err != nil {
			return nil, fmt.Errorf("failed to list GRPCBackends for cross-check: %w", err)
		}

		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.grpcBackends[grpcBackendCacheKey] = grpcBackends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(grpcBackendCacheKey)
		}
	}

	var conflicts []string
	for i := range grpcBackends.Items {
		existing := &grpcBackends.Items[i]
		if c.backendAndGRPCBackendConflict(existing.Spec.Hosts, graphqlBackend.Spec.Hosts) {
			conflicts = append(conflicts,
				"GRPCBackend:"+keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}
	return conflicts, nil
}

// CheckBackendCrossConflictsWithGraphQL checks if a Backend has host:port conflicts
// with existing GraphQLBackends.
func (c *DuplicateChecker) CheckBackendCrossConflictsWithGraphQL(
	ctx context.Context,
	backend *avapigwv1alpha1.Backend,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("graphqlbackend", backend.Namespace)
	var graphqlBackends *avapigwv1alpha1.GraphQLBackendList

	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			graphqlBackends = c.cache.graphqlBackends[cacheKey]
		}
		c.cache.mu.RUnlock()
	}

	if graphqlBackends == nil {
		graphqlBackends = &avapigwv1alpha1.GraphQLBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(backend.Namespace))
		}
		if err := c.client.List(ctx, graphqlBackends, listOpts...); err != nil {
			return fmt.Errorf("failed to list GraphQLBackends for cross-check: %w", err)
		}

		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.graphqlBackends[cacheKey] = graphqlBackends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	var conflicts []string
	for i := range graphqlBackends.Items {
		existing := &graphqlBackends.Items[i]
		if c.backendAndGRPCBackendConflict(backend.Spec.Hosts, existing.Spec.Hosts) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("cross-CRD Backend/GraphQLBackend conflict detected",
			observability.String("backend", keys.ResourceKey(backend.Namespace, backend.Name)),
			observability.Any("conflicting_graphqlbackends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"Backend %s/%s has host:port conflict with GraphQLBackend(s) %s",
			backend.Namespace, backend.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

// ============================================================================
// REST/GraphQL Cross-Route Intersection Detection
// ============================================================================

// CheckAPIRouteCrossConflictsWithGraphQL checks if an APIRoute has path conflicts
// with existing GraphQLRoutes. This prevents REST and GraphQL endpoints from
// overlapping on the same path, which would cause routing ambiguity.
func (c *DuplicateChecker) CheckAPIRouteCrossConflictsWithGraphQL(
	ctx context.Context,
	apiRoute *avapigwv1alpha1.APIRoute,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "apiroute"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey("graphqlroute", apiRoute.Namespace)
	var graphqlRoutes *avapigwv1alpha1.GraphQLRouteList

	// Try to use cached data under a single RLock to avoid TOCTOU race.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			graphqlRoutes = c.cache.graphqlRoutes[cacheKey]
		}
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if graphqlRoutes == nil {
		graphqlRoutes = &avapigwv1alpha1.GraphQLRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(apiRoute.Namespace))
		}
		if err := c.client.List(ctx, graphqlRoutes, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list GraphQLRoutes for cross-check: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.graphqlRoutes[cacheKey] = graphqlRoutes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for path conflicts between APIRoute and GraphQLRoutes
	var conflicts []string
	for i := range graphqlRoutes.Items {
		existing := &graphqlRoutes.Items[i]
		if c.apiRouteAndGraphQLRouteOverlap(apiRoute, existing) {
			conflicts = append(conflicts,
				"GraphQLRoute:"+keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("cross-CRD APIRoute/GraphQLRoute path conflict detected",
			observability.String("apiroute", keys.ResourceKey(apiRoute.Namespace, apiRoute.Name)),
			observability.Any("conflicting_graphqlroutes", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"APIRoute %s/%s has path conflict with %s",
			apiRoute.Namespace, apiRoute.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// CheckGraphQLRouteCrossConflictsWithAPIRoute checks if a GraphQLRoute has path conflicts
// with existing APIRoutes. This prevents GraphQL and REST endpoints from
// overlapping on the same path, which would cause routing ambiguity.
func (c *DuplicateChecker) CheckGraphQLRouteCrossConflictsWithAPIRoute(
	ctx context.Context,
	graphqlRoute *avapigwv1alpha1.GraphQLRoute,
) error {
	if c.client == nil {
		return nil
	}

	startTime := time.Now()
	scope := c.getScopeLabel()
	resourceType := "graphqlroute"

	dm := getDuplicateMetrics()
	defer func() {
		dm.checkDuration.WithLabelValues(resourceType, scope).Observe(time.Since(startTime).Seconds())
	}()

	cacheKey := c.buildCacheKey("apiroute", graphqlRoute.Namespace)
	var apiRoutes *avapigwv1alpha1.APIRouteList

	// Try to use cached data under a single RLock to avoid TOCTOU race.
	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			apiRoutes = c.cache.apiRoutes[cacheKey]
		}
		c.cache.mu.RUnlock()
	}

	// Fetch from API if cache miss or invalid
	if apiRoutes == nil {
		apiRoutes = &avapigwv1alpha1.APIRouteList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(graphqlRoute.Namespace))
		}
		if err := c.client.List(ctx, apiRoutes, listOpts...); err != nil {
			dm.checkTotal.WithLabelValues(resourceType, scope, "error").Inc()
			return fmt.Errorf("failed to list APIRoutes for cross-check: %w", err)
		}

		// Update cache
		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.apiRoutes[cacheKey] = apiRoutes
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	// Check for path conflicts between GraphQLRoute and APIRoutes
	var conflicts []string
	for i := range apiRoutes.Items {
		existing := &apiRoutes.Items[i]
		if c.graphqlRouteAndAPIRouteOverlap(graphqlRoute, existing) {
			conflicts = append(conflicts,
				"APIRoute:"+keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		dm.checkTotal.WithLabelValues(resourceType, scope, "conflict").Inc()
		c.logger.Warn("cross-CRD GraphQLRoute/APIRoute path conflict detected",
			observability.String("graphqlroute",
				keys.ResourceKey(graphqlRoute.Namespace, graphqlRoute.Name)),
			observability.Any("conflicting_apiroutes", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"GraphQLRoute %s/%s has path conflict with %s",
			graphqlRoute.Namespace, graphqlRoute.Name, strings.Join(conflicts, ", "))
	}

	dm.checkTotal.WithLabelValues(resourceType, scope, "ok").Inc()
	return nil
}

// apiRouteAndGraphQLRouteOverlap checks if an APIRoute and a GraphQLRoute have overlapping paths.
func (c *DuplicateChecker) apiRouteAndGraphQLRouteOverlap(
	apiRoute *avapigwv1alpha1.APIRoute,
	graphqlRoute *avapigwv1alpha1.GraphQLRoute,
) bool {
	// An empty match list means "catch-all" — it matches everything.
	// If either route is a catch-all, it overlaps with any other route.
	if len(apiRoute.Spec.Match) == 0 || len(graphqlRoute.Spec.Match) == 0 {
		return true
	}

	for i := range apiRoute.Spec.Match {
		apiMatch := &apiRoute.Spec.Match[i]
		for j := range graphqlRoute.Spec.Match {
			graphqlMatch := &graphqlRoute.Spec.Match[j]
			if c.apiRouteAndGraphQLRoutePathsOverlap(apiMatch, graphqlMatch) {
				return true
			}
		}
	}
	return false
}

// graphqlRouteAndAPIRouteOverlap checks if a GraphQLRoute and an APIRoute have overlapping paths.
// This is the reverse direction of apiRouteAndGraphQLRouteOverlap for symmetry.
func (c *DuplicateChecker) graphqlRouteAndAPIRouteOverlap(
	graphqlRoute *avapigwv1alpha1.GraphQLRoute,
	apiRoute *avapigwv1alpha1.APIRoute,
) bool {
	return c.apiRouteAndGraphQLRouteOverlap(apiRoute, graphqlRoute)
}

// apiRouteAndGraphQLRoutePathsOverlap checks if an APIRoute match and a GraphQLRoute match
// have overlapping paths. Path overlap alone is considered a conflict because REST and GraphQL
// routes serving on the same path would cause routing ambiguity regardless of operation type.
func (c *DuplicateChecker) apiRouteAndGraphQLRoutePathsOverlap(
	apiMatch *avapigwv1alpha1.RouteMatch,
	graphqlMatch *avapigwv1alpha1.GraphQLRouteMatch,
) bool {
	// If the APIRoute has no URI match, it matches all paths
	if apiMatch.URI == nil {
		return true
	}

	// If the GraphQLRoute has no path match, it matches all paths
	if graphqlMatch.Path == nil {
		return true
	}

	// Check exact-exact overlap
	if apiMatch.URI.Exact != "" && graphqlMatch.Path.Exact != "" {
		return apiMatch.URI.Exact == graphqlMatch.Path.Exact
	}

	// Check prefix-prefix overlap
	if apiMatch.URI.Prefix != "" && graphqlMatch.Path.Prefix != "" {
		return strings.HasPrefix(apiMatch.URI.Prefix, graphqlMatch.Path.Prefix) ||
			strings.HasPrefix(graphqlMatch.Path.Prefix, apiMatch.URI.Prefix)
	}

	// Check exact-prefix overlap (APIRoute exact vs GraphQLRoute prefix)
	if apiMatch.URI.Exact != "" && graphqlMatch.Path.Prefix != "" {
		return strings.HasPrefix(apiMatch.URI.Exact, graphqlMatch.Path.Prefix)
	}

	// Check prefix-exact overlap (APIRoute prefix vs GraphQLRoute exact)
	if apiMatch.URI.Prefix != "" && graphqlMatch.Path.Exact != "" {
		return strings.HasPrefix(graphqlMatch.Path.Exact, apiMatch.URI.Prefix)
	}

	return false
}

// CheckGRPCBackendCrossConflictsWithGraphQL checks if a GRPCBackend has host:port conflicts
// with existing GraphQLBackends.
func (c *DuplicateChecker) CheckGRPCBackendCrossConflictsWithGraphQL(
	ctx context.Context,
	grpcBackend *avapigwv1alpha1.GRPCBackend,
) error {
	if c.client == nil {
		return nil
	}

	cacheKey := c.buildCacheKey("graphqlbackend", grpcBackend.Namespace)
	var graphqlBackends *avapigwv1alpha1.GraphQLBackendList

	if c.cacheEnabled {
		c.cache.mu.RLock()
		if c.isCacheValidLocked(cacheKey) {
			graphqlBackends = c.cache.graphqlBackends[cacheKey]
		}
		c.cache.mu.RUnlock()
	}

	if graphqlBackends == nil {
		graphqlBackends = &avapigwv1alpha1.GraphQLBackendList{}
		listOpts := []client.ListOption{}
		if c.namespaceScoped.Load() {
			listOpts = append(listOpts, client.InNamespace(grpcBackend.Namespace))
		}
		if err := c.client.List(ctx, graphqlBackends, listOpts...); err != nil {
			return fmt.Errorf("failed to list GraphQLBackends for cross-check: %w", err)
		}

		if c.cacheEnabled {
			c.cache.mu.Lock()
			c.cache.graphqlBackends[cacheKey] = graphqlBackends
			c.cache.mu.Unlock()
			c.updateCacheTimestamp(cacheKey)
		}
	}

	var conflicts []string
	for i := range graphqlBackends.Items {
		existing := &graphqlBackends.Items[i]
		if c.backendAndGRPCBackendConflict(grpcBackend.Spec.Hosts, existing.Spec.Hosts) {
			conflicts = append(conflicts, keys.ResourceKey(existing.Namespace, existing.Name))
		}
	}

	if len(conflicts) > 0 {
		c.logger.Warn("cross-CRD GRPCBackend/GraphQLBackend conflict detected",
			observability.String("grpcbackend", keys.ResourceKey(grpcBackend.Namespace, grpcBackend.Name)),
			observability.Any("conflicting_graphqlbackends", conflicts),
		)
		//nolint:staticcheck // Error message is intentionally capitalized for resource name consistency
		return fmt.Errorf(
			"GRPCBackend %s/%s has host:port conflict with GraphQLBackend(s) %s",
			grpcBackend.Namespace, grpcBackend.Name, strings.Join(conflicts, ", "))
	}

	return nil
}

//go:build functional

// Package operator_test contains functional tests for the operator.
package operator_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vyrodovalexey/avapigw/internal/operator/webhook"
)

// ============================================================================
// Functional Tests: DuplicateChecker with Context (MAJOR-7, CRITICAL-4)
// ============================================================================

// TestFunctional_DuplicateChecker_ContextCancellation verifies that the
// DuplicateChecker cleanup goroutine stops when the context is canceled.
// This tests the fix for MAJOR-7 (cleanup goroutine leak).
func TestFunctional_DuplicateChecker_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	dc := webhook.NewDuplicateCheckerWithContext(ctx, nil,
		webhook.WithCacheEnabled(true),
		webhook.WithCleanupInterval(50*time.Millisecond),
		webhook.WithCacheTTL(100*time.Millisecond),
	)

	// Let the cleanup goroutine run a few cycles
	time.Sleep(200 * time.Millisecond)

	// Cancel the context - cleanup goroutine should stop
	cancel()

	// Give it time to stop
	time.Sleep(100 * time.Millisecond)

	// Verify the checker is still usable (no panic)
	scope := dc.GetScope()
	assert.Equal(t, webhook.ScopeNamespace, scope)
}

// TestFunctional_DuplicateChecker_StopMethod verifies that the Stop()
// method gracefully shuts down the cleanup goroutine.
func TestFunctional_DuplicateChecker_StopMethod(t *testing.T) {
	dc := webhook.NewDuplicateCheckerWithContext(context.Background(), nil,
		webhook.WithCacheEnabled(true),
		webhook.WithCleanupInterval(50*time.Millisecond),
		webhook.WithCacheTTL(100*time.Millisecond),
	)

	// Let the cleanup goroutine run
	time.Sleep(100 * time.Millisecond)

	// Stop should complete without hanging
	done := make(chan struct{})
	go func() {
		dc.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Stop completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not complete within timeout - possible goroutine leak")
	}
}

// TestFunctional_DuplicateChecker_SetScopeThreadSafe verifies that SetScope
// is thread-safe using atomic.Bool (CRITICAL-4 fix).
func TestFunctional_DuplicateChecker_SetScopeThreadSafe(t *testing.T) {
	dc := webhook.NewDuplicateCheckerWithContext(context.Background(), nil)

	var wg sync.WaitGroup
	const goroutines = 100

	// Concurrent SetScope and GetScope calls should not race
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if id%2 == 0 {
				dc.SetScope(webhook.ScopeNamespace)
			} else {
				dc.SetScope(webhook.ScopeCluster)
			}
			// Read scope concurrently
			_ = dc.GetScope()
		}(i)
	}

	wg.Wait()

	// Verify scope is one of the valid values
	scope := dc.GetScope()
	assert.True(t, scope == webhook.ScopeNamespace || scope == webhook.ScopeCluster,
		"scope should be a valid value, got %q", scope)
}

// TestFunctional_DuplicateChecker_CacheInvalidation verifies that cache
// invalidation works correctly.
func TestFunctional_DuplicateChecker_CacheInvalidation(t *testing.T) {
	dc := webhook.NewDuplicateCheckerWithContext(context.Background(), nil,
		webhook.WithCacheEnabled(true),
		webhook.WithCacheTTL(1*time.Hour),
	)

	// Invalidate cache should not panic
	dc.InvalidateCache()

	// Verify scope still works after invalidation
	scope := dc.GetScope()
	assert.Equal(t, webhook.ScopeNamespace, scope)
}

// TestFunctional_DuplicateChecker_DefaultConfig verifies that the default
// configuration creates a properly configured DuplicateChecker.
func TestFunctional_DuplicateChecker_DefaultConfig(t *testing.T) {
	cfg := webhook.DefaultDuplicateCheckerConfig()

	assert.False(t, cfg.ClusterWide, "default should be namespace-scoped")
	assert.True(t, cfg.CacheEnabled, "default should have cache enabled")
	assert.Greater(t, cfg.CacheTTL, time.Duration(0), "default cache TTL should be positive")
}

// TestFunctional_DuplicateChecker_FromConfig verifies creating a
// DuplicateChecker from a config struct.
func TestFunctional_DuplicateChecker_FromConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := webhook.DuplicateCheckerConfig{
		ClusterWide:  true,
		CacheEnabled: true,
		CacheTTL:     5 * time.Second,
	}

	dc := webhook.NewDuplicateCheckerFromConfigWithContext(ctx, nil, cfg)

	// Cluster-wide means not namespace-scoped
	assert.Equal(t, webhook.ScopeCluster, dc.GetScope())
}

// TestFunctional_DuplicateChecker_NoCacheNoGoroutine verifies that when
// caching is disabled, no cleanup goroutine is started.
func TestFunctional_DuplicateChecker_NoCacheNoGoroutine(t *testing.T) {
	dc := webhook.NewDuplicateCheckerWithContext(context.Background(), nil,
		webhook.WithCacheEnabled(false),
	)

	// Stop should be a no-op when cache is disabled
	// (no goroutine to stop, should not hang)
	done := make(chan struct{})
	go func() {
		dc.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Stop completed immediately
	case <-time.After(1 * time.Second):
		t.Fatal("Stop() should be immediate when cache is disabled")
	}
}

// TestFunctional_DuplicateChecker_WithNamespaceScoped verifies the
// WithNamespaceScoped option.
func TestFunctional_DuplicateChecker_WithNamespaceScoped(t *testing.T) {
	t.Run("namespace scoped", func(t *testing.T) {
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), nil,
			webhook.WithNamespaceScoped(true),
		)
		assert.Equal(t, webhook.ScopeNamespace, dc.GetScope())
	})

	t.Run("cluster scoped", func(t *testing.T) {
		dc := webhook.NewDuplicateCheckerWithContext(context.Background(), nil,
			webhook.WithNamespaceScoped(false),
		)
		assert.Equal(t, webhook.ScopeCluster, dc.GetScope())
	})
}

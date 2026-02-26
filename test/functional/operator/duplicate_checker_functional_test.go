//go:build functional

// Package operator_test contains functional tests for the operator.
package operator_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	avapigwv1alpha1 "github.com/vyrodovalexey/avapigw/api/v1alpha1"
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

// ============================================================================
// Cross-CRD Route Conflict Detection (TC-CROSS-001..006)
// ============================================================================

// TestFunctional_DuplicateChecker_CrossCRDRouteConflict tests cross-CRD route
// conflict detection between APIRoute and GraphQLRoute.
func TestFunctional_DuplicateChecker_CrossCRDRouteConflict(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	require.NoError(t, avapigwv1alpha1.AddToScheme(scheme))

	t.Run("APIRoute prefix conflicts with GraphQLRoute exact path", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821},
						Weight:      100,
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingGraphQL).
			Build()

		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient)
		defer dc.Stop()

		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route-conflict",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/graphql"},
					},
				},
			},
		}

		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
		assert.Contains(t, err.Error(), "GraphQLRoute")
	})

	t.Run("GraphQLRoute exact path conflicts with APIRoute prefix", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		existingAPIRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/api"},
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingAPIRoute).
			Build()

		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient)
		defer dc.Stop()

		graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route-conflict",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/api/graphql"},
					},
				},
			},
		}

		err := dc.CheckGraphQLRouteCrossConflictsWithAPIRoute(ctx, graphqlRoute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
		assert.Contains(t, err.Error(), "APIRoute")
	})

	t.Run("no conflict with different paths", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route-safe",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821},
						Weight:      100,
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingGraphQL).
			Build()

		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient)
		defer dc.Stop()

		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route-safe",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/api/v1"},
					},
				},
			},
		}

		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		assert.NoError(t, err)
	})

	t.Run("cross-namespace conflict detection with cluster scope", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// GraphQLRoute in namespace "ns-a"
		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route-ns-a",
				Namespace: "ns-a",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821},
						Weight:      100,
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingGraphQL).
			Build()

		// Cluster-scoped checker should detect cross-namespace conflicts
		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient,
			webhook.WithNamespaceScoped(false),
		)
		defer dc.Stop()

		// APIRoute in namespace "ns-b" with conflicting path
		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route-ns-b",
				Namespace: "ns-b",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/graphql"},
					},
				},
			},
		}

		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
	})

	t.Run("namespace-scoped checker does not detect cross-namespace conflicts", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// GraphQLRoute in namespace "ns-a"
		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route-ns-a",
				Namespace: "ns-a",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821},
						Weight:      100,
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingGraphQL).
			Build()

		// Namespace-scoped checker should NOT detect cross-namespace conflicts
		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient,
			webhook.WithNamespaceScoped(true),
		)
		defer dc.Stop()

		// APIRoute in namespace "ns-b" — different namespace, so no conflict
		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route-ns-b",
				Namespace: "ns-b",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/graphql"},
					},
				},
			},
		}

		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		assert.NoError(t, err)
	})

	t.Run("nil client returns no error", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		dc := webhook.NewDuplicateCheckerWithContext(ctx, nil)

		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/graphql"},
					},
				},
			},
		}

		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		assert.NoError(t, err)

		graphqlRoute := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
			},
		}

		err = dc.CheckGraphQLRouteCrossConflictsWithAPIRoute(ctx, graphqlRoute)
		assert.NoError(t, err)
	})

	t.Run("catch-all APIRoute conflicts with any GraphQLRoute", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route-any",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821},
						Weight:      100,
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingGraphQL).
			Build()

		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient)
		defer dc.Stop()

		// APIRoute with empty match (catch-all)
		catchAllAPIRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route-catch-all",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{},
			},
		}

		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, catchAllAPIRoute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
	})

	t.Run("with cache enabled detects conflicts", func(t *testing.T) {
		t.Parallel()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		existingGraphQL := &avapigwv1alpha1.GraphQLRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "graphql-route-cached",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.GraphQLRouteSpec{
				Match: []avapigwv1alpha1.GraphQLRouteMatch{
					{
						Path: &avapigwv1alpha1.StringMatch{Exact: "/graphql"},
					},
				},
				Route: []avapigwv1alpha1.RouteDestination{
					{
						Destination: avapigwv1alpha1.Destination{Host: "graphql-backend", Port: 8821},
						Weight:      100,
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(scheme).
			WithObjects(existingGraphQL).
			Build()

		dc := webhook.NewDuplicateCheckerWithContext(ctx, fakeClient,
			webhook.WithCacheEnabled(true),
			webhook.WithCacheTTL(1*time.Minute),
		)
		defer dc.Stop()

		apiRoute := &avapigwv1alpha1.APIRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "api-route-cached-conflict",
				Namespace: "default",
			},
			Spec: avapigwv1alpha1.APIRouteSpec{
				Match: []avapigwv1alpha1.RouteMatch{
					{
						URI: &avapigwv1alpha1.URIMatch{Prefix: "/graphql"},
					},
				},
			},
		}

		// First call populates cache
		err := dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")

		// Second call should use cache and still detect conflict
		err = dc.CheckAPIRouteCrossConflictsWithGraphQL(ctx, apiRoute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path conflict")
	})
}

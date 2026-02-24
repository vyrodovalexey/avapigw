// Package grpc provides comprehensive tests for GraphQL-related server methods.
// These tests cover ApplyGraphQLRoute, DeleteGraphQLRoute, ApplyGraphQLBackend,
// DeleteGraphQLBackend, HasGraphQLRoute, and HasGraphQLBackend, along with their
// internal implementations.
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// ApplyGraphQLRoute Tests
// ============================================================================

func TestServer_ApplyGraphQLRoute_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()
	config := []byte(`{"match":[{"path":{"prefix":"/graphql"}}]}`)

	err = srv.ApplyGraphQLRoute(ctx, "graphql-route-1", "default", config)
	require.NoError(t, err)

	// Verify the route was stored
	srv.mu.RLock()
	stored, ok := srv.graphqlRoutes["default/graphql-route-1"]
	srv.mu.RUnlock()

	assert.True(t, ok, "ApplyGraphQLRoute should store the route")
	assert.Equal(t, config, stored, "stored config should match input")
}

func TestServer_ApplyGraphQLRoute_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		routeName string
		namespace string
		config    []byte
		wantKey   string
	}{
		{
			name:      "standard route",
			routeName: "my-graphql-route",
			namespace: "default",
			config:    []byte(`{"match":[{"path":{"prefix":"/graphql"}}]}`),
			wantKey:   "default/my-graphql-route",
		},
		{
			name:      "route in custom namespace",
			routeName: "graphql-api",
			namespace: "production",
			config:    []byte(`{"match":[{"path":{"exact":"/api/graphql"}}]}`),
			wantKey:   "production/graphql-api",
		},
		{
			name:      "empty config",
			routeName: "empty-route",
			namespace: "default",
			config:    []byte{},
			wantKey:   "default/empty-route",
		},
		{
			name:      "nil config",
			routeName: "nil-route",
			namespace: "default",
			config:    nil,
			wantKey:   "default/nil-route",
		},
		{
			name:      "empty name",
			routeName: "",
			namespace: "default",
			config:    []byte(`{}`),
			wantKey:   "default/",
		},
		{
			name:      "empty namespace",
			routeName: "route1",
			namespace: "",
			config:    []byte(`{}`),
			wantKey:   "/route1",
		},
		{
			name:      "large config payload",
			routeName: "large-route",
			namespace: "default",
			config:    make([]byte, 1024*1024), // 1MB
			wantKey:   "default/large-route",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx := context.Background()
			err = srv.ApplyGraphQLRoute(ctx, tt.routeName, tt.namespace, tt.config)
			require.NoError(t, err)

			srv.mu.RLock()
			stored, ok := srv.graphqlRoutes[tt.wantKey]
			srv.mu.RUnlock()

			assert.True(t, ok, "route should be stored under key %q", tt.wantKey)
			assert.Equal(t, tt.config, stored)
		})
	}
}

func TestServer_ApplyGraphQLRoute_Overwrite(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply initial config
	config1 := []byte(`{"version":"v1"}`)
	err = srv.ApplyGraphQLRoute(ctx, "route1", "default", config1)
	require.NoError(t, err)

	// Overwrite with new config
	config2 := []byte(`{"version":"v2"}`)
	err = srv.ApplyGraphQLRoute(ctx, "route1", "default", config2)
	require.NoError(t, err)

	// Verify the latest config is stored
	srv.mu.RLock()
	stored, ok := srv.graphqlRoutes["default/route1"]
	srv.mu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, config2, stored, "should store the latest config")
}

func TestServer_ApplyGraphQLRoute_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = srv.ApplyGraphQLRoute(ctx, "route1", "default", []byte(`{}`))
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_ApplyGraphQLRoute_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err = srv.ApplyGraphQLRoute(ctx, "route1", "default", []byte(`{}`))
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestServer_ApplyGraphQLRoute_NotifiesConfigChange(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	// Get the notification channel before applying
	waitCh := srv.WaitForConfigChange()

	ctx := context.Background()
	err = srv.ApplyGraphQLRoute(ctx, "route1", "default", []byte(`{}`))
	require.NoError(t, err)

	// The channel should be closed (signaling a config change)
	select {
	case <-waitCh:
		// Success - channel was closed
	case <-time.After(1 * time.Second):
		t.Error("ApplyGraphQLRoute should notify config change")
	}
}

// ============================================================================
// applyGraphQLRouteInternal Tests
// ============================================================================

func TestServer_applyGraphQLRouteInternal_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()
	config := []byte(`{"internal":"test"}`)

	err = srv.applyGraphQLRouteInternal(ctx, "internal-route", "ns1", config)
	require.NoError(t, err)

	srv.mu.RLock()
	stored, ok := srv.graphqlRoutes["ns1/internal-route"]
	srv.mu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, config, stored)
}

func TestServer_applyGraphQLRouteInternal_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.applyGraphQLRouteInternal(ctx, "route1", "default", []byte(`{}`))
	assert.Error(t, err)
}

// ============================================================================
// DeleteGraphQLRoute Tests
// ============================================================================

func TestServer_DeleteGraphQLRoute_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()
	config := []byte(`{"match":[{"path":{"prefix":"/graphql"}}]}`)

	// First apply a route
	err = srv.ApplyGraphQLRoute(ctx, "graphql-route-1", "default", config)
	require.NoError(t, err)

	// Then delete it
	err = srv.DeleteGraphQLRoute(ctx, "graphql-route-1", "default")
	require.NoError(t, err)

	// Verify the route was deleted
	srv.mu.RLock()
	_, ok := srv.graphqlRoutes["default/graphql-route-1"]
	srv.mu.RUnlock()

	assert.False(t, ok, "DeleteGraphQLRoute should remove the route")
}

func TestServer_DeleteGraphQLRoute_NonExistent(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Delete a route that doesn't exist - should not error
	err = srv.DeleteGraphQLRoute(ctx, "non-existent", "default")
	assert.NoError(t, err)
}

func TestServer_DeleteGraphQLRoute_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.DeleteGraphQLRoute(ctx, "route1", "default")
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_DeleteGraphQLRoute_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err = srv.DeleteGraphQLRoute(ctx, "route1", "default")
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestServer_DeleteGraphQLRoute_NotifiesConfigChange(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply a route first
	err = srv.ApplyGraphQLRoute(ctx, "route1", "default", []byte(`{}`))
	require.NoError(t, err)

	// Get the notification channel before deleting
	waitCh := srv.WaitForConfigChange()

	err = srv.DeleteGraphQLRoute(ctx, "route1", "default")
	require.NoError(t, err)

	// The channel should be closed (signaling a config change)
	select {
	case <-waitCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("DeleteGraphQLRoute should notify config change")
	}
}

// ============================================================================
// deleteGraphQLRouteInternal Tests
// ============================================================================

func TestServer_deleteGraphQLRouteInternal_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Pre-populate
	srv.mu.Lock()
	srv.graphqlRoutes["ns1/internal-route"] = []byte(`{"data":"test"}`)
	srv.mu.Unlock()

	err = srv.deleteGraphQLRouteInternal(ctx, "internal-route", "ns1")
	require.NoError(t, err)

	srv.mu.RLock()
	_, ok := srv.graphqlRoutes["ns1/internal-route"]
	srv.mu.RUnlock()

	assert.False(t, ok)
}

func TestServer_deleteGraphQLRouteInternal_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.deleteGraphQLRouteInternal(ctx, "route1", "default")
	assert.Error(t, err)
}

// ============================================================================
// ApplyGraphQLBackend Tests
// ============================================================================

func TestServer_ApplyGraphQLBackend_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()
	config := []byte(`{"hosts":[{"address":"graphql-backend","port":8080}]}`)

	err = srv.ApplyGraphQLBackend(ctx, "graphql-backend-1", "default", config)
	require.NoError(t, err)

	// Verify the backend was stored
	srv.mu.RLock()
	stored, ok := srv.graphqlBackends["default/graphql-backend-1"]
	srv.mu.RUnlock()

	assert.True(t, ok, "ApplyGraphQLBackend should store the backend")
	assert.Equal(t, config, stored, "stored config should match input")
}

func TestServer_ApplyGraphQLBackend_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		backendName string
		namespace   string
		config      []byte
		wantKey     string
	}{
		{
			name:        "standard backend",
			backendName: "my-graphql-backend",
			namespace:   "default",
			config:      []byte(`{"hosts":[{"address":"graphql-svc","port":8080}]}`),
			wantKey:     "default/my-graphql-backend",
		},
		{
			name:        "backend in custom namespace",
			backendName: "graphql-api-backend",
			namespace:   "staging",
			config:      []byte(`{"hosts":[{"address":"graphql-staging","port":9090}]}`),
			wantKey:     "staging/graphql-api-backend",
		},
		{
			name:        "empty config",
			backendName: "empty-backend",
			namespace:   "default",
			config:      []byte{},
			wantKey:     "default/empty-backend",
		},
		{
			name:        "nil config",
			backendName: "nil-backend",
			namespace:   "default",
			config:      nil,
			wantKey:     "default/nil-backend",
		},
		{
			name:        "empty name",
			backendName: "",
			namespace:   "default",
			config:      []byte(`{}`),
			wantKey:     "default/",
		},
		{
			name:        "empty namespace",
			backendName: "backend1",
			namespace:   "",
			config:      []byte(`{}`),
			wantKey:     "/backend1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx := context.Background()
			err = srv.ApplyGraphQLBackend(ctx, tt.backendName, tt.namespace, tt.config)
			require.NoError(t, err)

			srv.mu.RLock()
			stored, ok := srv.graphqlBackends[tt.wantKey]
			srv.mu.RUnlock()

			assert.True(t, ok, "backend should be stored under key %q", tt.wantKey)
			assert.Equal(t, tt.config, stored)
		})
	}
}

func TestServer_ApplyGraphQLBackend_Overwrite(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply initial config
	config1 := []byte(`{"version":"v1"}`)
	err = srv.ApplyGraphQLBackend(ctx, "backend1", "default", config1)
	require.NoError(t, err)

	// Overwrite with new config
	config2 := []byte(`{"version":"v2"}`)
	err = srv.ApplyGraphQLBackend(ctx, "backend1", "default", config2)
	require.NoError(t, err)

	// Verify the latest config is stored
	srv.mu.RLock()
	stored, ok := srv.graphqlBackends["default/backend1"]
	srv.mu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, config2, stored, "should store the latest config")
}

func TestServer_ApplyGraphQLBackend_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.ApplyGraphQLBackend(ctx, "backend1", "default", []byte(`{}`))
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_ApplyGraphQLBackend_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err = srv.ApplyGraphQLBackend(ctx, "backend1", "default", []byte(`{}`))
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestServer_ApplyGraphQLBackend_NotifiesConfigChange(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	waitCh := srv.WaitForConfigChange()

	ctx := context.Background()
	err = srv.ApplyGraphQLBackend(ctx, "backend1", "default", []byte(`{}`))
	require.NoError(t, err)

	select {
	case <-waitCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("ApplyGraphQLBackend should notify config change")
	}
}

// ============================================================================
// applyGraphQLBackendInternal Tests
// ============================================================================

func TestServer_applyGraphQLBackendInternal_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()
	config := []byte(`{"internal":"backend-test"}`)

	err = srv.applyGraphQLBackendInternal(ctx, "internal-backend", "ns1", config)
	require.NoError(t, err)

	srv.mu.RLock()
	stored, ok := srv.graphqlBackends["ns1/internal-backend"]
	srv.mu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, config, stored)
}

func TestServer_applyGraphQLBackendInternal_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.applyGraphQLBackendInternal(ctx, "backend1", "default", []byte(`{}`))
	assert.Error(t, err)
}

// ============================================================================
// DeleteGraphQLBackend Tests
// ============================================================================

func TestServer_DeleteGraphQLBackend_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()
	config := []byte(`{"hosts":[{"address":"graphql-backend","port":8080}]}`)

	// First apply a backend
	err = srv.ApplyGraphQLBackend(ctx, "graphql-backend-1", "default", config)
	require.NoError(t, err)

	// Then delete it
	err = srv.DeleteGraphQLBackend(ctx, "graphql-backend-1", "default")
	require.NoError(t, err)

	// Verify the backend was deleted
	srv.mu.RLock()
	_, ok := srv.graphqlBackends["default/graphql-backend-1"]
	srv.mu.RUnlock()

	assert.False(t, ok, "DeleteGraphQLBackend should remove the backend")
}

func TestServer_DeleteGraphQLBackend_NonExistent(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Delete a backend that doesn't exist - should not error
	err = srv.DeleteGraphQLBackend(ctx, "non-existent", "default")
	assert.NoError(t, err)
}

func TestServer_DeleteGraphQLBackend_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.DeleteGraphQLBackend(ctx, "backend1", "default")
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestServer_DeleteGraphQLBackend_ContextDeadlineExceeded(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
	defer cancel()

	err = srv.DeleteGraphQLBackend(ctx, "backend1", "default")
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestServer_DeleteGraphQLBackend_NotifiesConfigChange(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply a backend first
	err = srv.ApplyGraphQLBackend(ctx, "backend1", "default", []byte(`{}`))
	require.NoError(t, err)

	// Get the notification channel before deleting
	waitCh := srv.WaitForConfigChange()

	err = srv.DeleteGraphQLBackend(ctx, "backend1", "default")
	require.NoError(t, err)

	select {
	case <-waitCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("DeleteGraphQLBackend should notify config change")
	}
}

// ============================================================================
// deleteGraphQLBackendInternal Tests
// ============================================================================

func TestServer_deleteGraphQLBackendInternal_Success(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Pre-populate
	srv.mu.Lock()
	srv.graphqlBackends["ns1/internal-backend"] = []byte(`{"data":"test"}`)
	srv.mu.Unlock()

	err = srv.deleteGraphQLBackendInternal(ctx, "internal-backend", "ns1")
	require.NoError(t, err)

	srv.mu.RLock()
	_, ok := srv.graphqlBackends["ns1/internal-backend"]
	srv.mu.RUnlock()

	assert.False(t, ok)
}

func TestServer_deleteGraphQLBackendInternal_ContextCanceled(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.deleteGraphQLBackendInternal(ctx, "backend1", "default")
	assert.Error(t, err)
}

// ============================================================================
// HasGraphQLRoute Tests
// ============================================================================

func TestServer_HasGraphQLRoute(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(ctx context.Context, srv *Server)
		checkName string
		checkNS   string
		expected  bool
	}{
		{
			name:      "returns false for empty server",
			setup:     func(_ context.Context, _ *Server) {},
			checkName: "graphql-route1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true for existing route",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "graphql-route1", "default", []byte(`{"path":"/graphql"}`)))
			},
			checkName: "graphql-route1",
			checkNS:   "default",
			expected:  true,
		},
		{
			name: "returns false for wrong name",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "graphql-route1", "default", []byte(`{}`)))
			},
			checkName: "graphql-route2",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns false for wrong namespace",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "graphql-route1", "default", []byte(`{}`)))
			},
			checkName: "graphql-route1",
			checkNS:   "other-ns",
			expected:  false,
		},
		{
			name: "returns false after deletion",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "graphql-route1", "default", []byte(`{}`)))
				require.NoError(t, srv.DeleteGraphQLRoute(ctx, "graphql-route1", "default"))
			},
			checkName: "graphql-route1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true with multiple routes - checks correct one",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "route-a", "ns1", []byte(`{}`)))
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "route-b", "ns1", []byte(`{}`)))
				require.NoError(t, srv.ApplyGraphQLRoute(ctx, "route-a", "ns2", []byte(`{}`)))
			},
			checkName: "route-b",
			checkNS:   "ns1",
			expected:  true,
		},
		{
			name:      "returns false for empty name and namespace",
			setup:     func(_ context.Context, _ *Server) {},
			checkName: "",
			checkNS:   "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx := context.Background()
			tt.setup(ctx, srv)

			result := srv.HasGraphQLRoute(tt.checkName, tt.checkNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// HasGraphQLBackend Tests
// ============================================================================

func TestServer_HasGraphQLBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(ctx context.Context, srv *Server)
		checkName string
		checkNS   string
		expected  bool
	}{
		{
			name:      "returns false for empty server",
			setup:     func(_ context.Context, _ *Server) {},
			checkName: "graphql-backend1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true for existing backend",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "graphql-backend1", "default", []byte(`{"host":"svc"}`)))
			},
			checkName: "graphql-backend1",
			checkNS:   "default",
			expected:  true,
		},
		{
			name: "returns false for wrong name",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "graphql-backend1", "default", []byte(`{}`)))
			},
			checkName: "graphql-backend2",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns false for wrong namespace",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "graphql-backend1", "default", []byte(`{}`)))
			},
			checkName: "graphql-backend1",
			checkNS:   "other-ns",
			expected:  false,
		},
		{
			name: "returns false after deletion",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "graphql-backend1", "default", []byte(`{}`)))
				require.NoError(t, srv.DeleteGraphQLBackend(ctx, "graphql-backend1", "default"))
			},
			checkName: "graphql-backend1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true with multiple backends - checks correct one",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "backend-a", "ns1", []byte(`{}`)))
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "backend-b", "ns1", []byte(`{}`)))
				require.NoError(t, srv.ApplyGraphQLBackend(ctx, "backend-a", "ns2", []byte(`{}`)))
			},
			checkName: "backend-b",
			checkNS:   "ns1",
			expected:  true,
		},
		{
			name:      "returns false for empty name and namespace",
			setup:     func(_ context.Context, _ *Server) {},
			checkName: "",
			checkNS:   "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx := context.Background()
			tt.setup(ctx, srv)

			result := srv.HasGraphQLBackend(tt.checkName, tt.checkNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// GraphQL Namespace Isolation Tests
// ============================================================================

func TestServer_GraphQLRoute_NamespaceIsolation(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply same-named routes in different namespaces
	config1 := []byte(`{"ns":"ns1"}`)
	config2 := []byte(`{"ns":"ns2"}`)

	err = srv.ApplyGraphQLRoute(ctx, "shared-route", "ns1", config1)
	require.NoError(t, err)

	err = srv.ApplyGraphQLRoute(ctx, "shared-route", "ns2", config2)
	require.NoError(t, err)

	// Verify both exist independently
	assert.True(t, srv.HasGraphQLRoute("shared-route", "ns1"))
	assert.True(t, srv.HasGraphQLRoute("shared-route", "ns2"))

	// Delete from one namespace
	err = srv.DeleteGraphQLRoute(ctx, "shared-route", "ns1")
	require.NoError(t, err)

	// Verify only ns1 is deleted
	assert.False(t, srv.HasGraphQLRoute("shared-route", "ns1"))
	assert.True(t, srv.HasGraphQLRoute("shared-route", "ns2"))

	// Verify ns2 config is intact
	srv.mu.RLock()
	stored, ok := srv.graphqlRoutes["ns2/shared-route"]
	srv.mu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, config2, stored)
}

func TestServer_GraphQLBackend_NamespaceIsolation(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply same-named backends in different namespaces
	config1 := []byte(`{"ns":"ns1"}`)
	config2 := []byte(`{"ns":"ns2"}`)

	err = srv.ApplyGraphQLBackend(ctx, "shared-backend", "ns1", config1)
	require.NoError(t, err)

	err = srv.ApplyGraphQLBackend(ctx, "shared-backend", "ns2", config2)
	require.NoError(t, err)

	// Verify both exist independently
	assert.True(t, srv.HasGraphQLBackend("shared-backend", "ns1"))
	assert.True(t, srv.HasGraphQLBackend("shared-backend", "ns2"))

	// Delete from one namespace
	err = srv.DeleteGraphQLBackend(ctx, "shared-backend", "ns1")
	require.NoError(t, err)

	// Verify only ns1 is deleted
	assert.False(t, srv.HasGraphQLBackend("shared-backend", "ns1"))
	assert.True(t, srv.HasGraphQLBackend("shared-backend", "ns2"))

	// Verify ns2 config is intact
	srv.mu.RLock()
	stored, ok := srv.graphqlBackends["ns2/shared-backend"]
	srv.mu.RUnlock()

	assert.True(t, ok)
	assert.Equal(t, config2, stored)
}

// ============================================================================
// GraphQL Multiple Operations Tests
// ============================================================================

func TestServer_GraphQL_MultipleOperations(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply multiple GraphQL routes and backends
	for i := 0; i < 10; i++ {
		name := "route-" + string(rune('a'+i))
		err = srv.ApplyGraphQLRoute(ctx, name, "default", []byte(`{}`))
		require.NoError(t, err)

		backendName := "backend-" + string(rune('a'+i))
		err = srv.ApplyGraphQLBackend(ctx, backendName, "default", []byte(`{}`))
		require.NoError(t, err)
	}

	// Verify counts
	srv.mu.RLock()
	routeCount := len(srv.graphqlRoutes)
	backendCount := len(srv.graphqlBackends)
	srv.mu.RUnlock()

	assert.Equal(t, 10, routeCount)
	assert.Equal(t, 10, backendCount)

	// Delete all
	for i := 0; i < 10; i++ {
		name := "route-" + string(rune('a'+i))
		err = srv.DeleteGraphQLRoute(ctx, name, "default")
		require.NoError(t, err)

		backendName := "backend-" + string(rune('a'+i))
		err = srv.DeleteGraphQLBackend(ctx, backendName, "default")
		require.NoError(t, err)
	}

	// Verify all deleted
	srv.mu.RLock()
	routeCount = len(srv.graphqlRoutes)
	backendCount = len(srv.graphqlBackends)
	srv.mu.RUnlock()

	assert.Equal(t, 0, routeCount)
	assert.Equal(t, 0, backendCount)
}

// ============================================================================
// GraphQL GetAllConfigs Integration Tests
// ============================================================================

func TestServer_GetAllConfigs_IncludesGraphQL(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
	require.NoError(t, err)

	ctx := context.Background()

	// Apply GraphQL routes and backends
	err = srv.ApplyGraphQLRoute(ctx, "gql-route1", "default", []byte(`{"path":"/graphql"}`))
	require.NoError(t, err)

	err = srv.ApplyGraphQLBackend(ctx, "gql-backend1", "default", []byte(`{"host":"graphql-svc"}`))
	require.NoError(t, err)

	// Get all configs
	configsJSON, err := srv.GetAllConfigs()
	require.NoError(t, err)
	assert.NotEmpty(t, configsJSON)

	// Verify GraphQL configs are included in the JSON output
	configStr := string(configsJSON)
	assert.Contains(t, configStr, "graphqlRoutes")
	assert.Contains(t, configStr, "graphqlBackends")
}

// ============================================================================
// GraphQL Apply/Delete with Context Cancellation - Table-Driven
// ============================================================================

func TestServer_GraphQL_ContextCancellation_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation func(ctx context.Context, srv *Server) error
	}{
		{
			name: "ApplyGraphQLRoute",
			operation: func(ctx context.Context, srv *Server) error {
				return srv.ApplyGraphQLRoute(ctx, "test", "ns", []byte(`{}`))
			},
		},
		{
			name: "DeleteGraphQLRoute",
			operation: func(ctx context.Context, srv *Server) error {
				return srv.DeleteGraphQLRoute(ctx, "test", "ns")
			},
		},
		{
			name: "ApplyGraphQLBackend",
			operation: func(ctx context.Context, srv *Server) error {
				return srv.ApplyGraphQLBackend(ctx, "test", "ns", []byte(`{}`))
			},
		},
		{
			name: "DeleteGraphQLBackend",
			operation: func(ctx context.Context, srv *Server) error {
				return srv.DeleteGraphQLBackend(ctx, "test", "ns")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_Canceled", func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			err = tt.operation(ctx, srv)
			assert.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
		})

		t.Run(tt.name+"_DeadlineExceeded", func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
			defer cancel()

			err = tt.operation(ctx, srv)
			assert.Error(t, err)
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		})
	}
}

// ============================================================================
// GraphQL Apply/Delete Success - Table-Driven
// ============================================================================

func TestServer_GraphQL_ApplyDelete_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		apply    func(ctx context.Context, srv *Server) error
		delete   func(ctx context.Context, srv *Server) error
		hasCheck func(srv *Server) bool
	}{
		{
			name: "GraphQL route",
			apply: func(ctx context.Context, srv *Server) error {
				return srv.ApplyGraphQLRoute(ctx, "test-route", "default", []byte(`{"path":"/graphql"}`))
			},
			delete: func(ctx context.Context, srv *Server) error {
				return srv.DeleteGraphQLRoute(ctx, "test-route", "default")
			},
			hasCheck: func(srv *Server) bool {
				return srv.HasGraphQLRoute("test-route", "default")
			},
		},
		{
			name: "GraphQL backend",
			apply: func(ctx context.Context, srv *Server) error {
				return srv.ApplyGraphQLBackend(ctx, "test-backend", "default", []byte(`{"host":"svc"}`))
			},
			delete: func(ctx context.Context, srv *Server) error {
				return srv.DeleteGraphQLBackend(ctx, "test-backend", "default")
			},
			hasCheck: func(srv *Server) bool {
				return srv.HasGraphQLBackend("test-backend", "default")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := prometheus.NewRegistry()
			srv, err := NewServerWithRegistry(&ServerConfig{}, reg)
			require.NoError(t, err)

			ctx := context.Background()

			// Initially should not exist
			assert.False(t, tt.hasCheck(srv), "should not exist before apply")

			// Apply
			err = tt.apply(ctx, srv)
			require.NoError(t, err)
			assert.True(t, tt.hasCheck(srv), "should exist after apply")

			// Delete
			err = tt.delete(ctx, srv)
			require.NoError(t, err)
			assert.False(t, tt.hasCheck(srv), "should not exist after delete")
		})
	}
}

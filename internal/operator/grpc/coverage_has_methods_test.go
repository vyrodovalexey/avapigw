// Package grpc provides additional tests for Has* methods and other uncovered paths.
package grpc

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// HasAPIRoute Tests
// ============================================================================

func TestServer_HasAPIRoute(t *testing.T) {
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
			checkName: "route1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true for existing route",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyAPIRoute(ctx, "route1", "default", []byte(`{"path":"/api"}`)))
			},
			checkName: "route1",
			checkNS:   "default",
			expected:  true,
		},
		{
			name: "returns false for wrong name",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyAPIRoute(ctx, "route1", "default", []byte(`{}`)))
			},
			checkName: "route2",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns false for wrong namespace",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyAPIRoute(ctx, "route1", "default", []byte(`{}`)))
			},
			checkName: "route1",
			checkNS:   "other-ns",
			expected:  false,
		},
		{
			name: "returns false after deletion",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyAPIRoute(ctx, "route1", "default", []byte(`{}`)))
				require.NoError(t, srv.DeleteAPIRoute(ctx, "route1", "default"))
			},
			checkName: "route1",
			checkNS:   "default",
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

			result := srv.HasAPIRoute(tt.checkName, tt.checkNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// HasGRPCRoute Tests
// ============================================================================

func TestServer_HasGRPCRoute(t *testing.T) {
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
			checkName: "grpc-route1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true for existing route",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGRPCRoute(ctx, "grpc-route1", "default", []byte(`{"service":"svc"}`)))
			},
			checkName: "grpc-route1",
			checkNS:   "default",
			expected:  true,
		},
		{
			name: "returns false for wrong name",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGRPCRoute(ctx, "grpc-route1", "default", []byte(`{}`)))
			},
			checkName: "grpc-route2",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns false after deletion",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGRPCRoute(ctx, "grpc-route1", "default", []byte(`{}`)))
				require.NoError(t, srv.DeleteGRPCRoute(ctx, "grpc-route1", "default"))
			},
			checkName: "grpc-route1",
			checkNS:   "default",
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

			result := srv.HasGRPCRoute(tt.checkName, tt.checkNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// HasBackend Tests
// ============================================================================

func TestServer_HasBackend(t *testing.T) {
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
			checkName: "backend1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true for existing backend",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyBackend(ctx, "backend1", "default", []byte(`{"host":"svc"}`)))
			},
			checkName: "backend1",
			checkNS:   "default",
			expected:  true,
		},
		{
			name: "returns false for wrong name",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyBackend(ctx, "backend1", "default", []byte(`{}`)))
			},
			checkName: "backend2",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns false after deletion",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyBackend(ctx, "backend1", "default", []byte(`{}`)))
				require.NoError(t, srv.DeleteBackend(ctx, "backend1", "default"))
			},
			checkName: "backend1",
			checkNS:   "default",
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

			result := srv.HasBackend(tt.checkName, tt.checkNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// HasGRPCBackend Tests
// ============================================================================

func TestServer_HasGRPCBackend(t *testing.T) {
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
			checkName: "grpc-backend1",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns true for existing backend",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGRPCBackend(ctx, "grpc-backend1", "default", []byte(`{"host":"svc"}`)))
			},
			checkName: "grpc-backend1",
			checkNS:   "default",
			expected:  true,
		},
		{
			name: "returns false for wrong name",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGRPCBackend(ctx, "grpc-backend1", "default", []byte(`{}`)))
			},
			checkName: "grpc-backend2",
			checkNS:   "default",
			expected:  false,
		},
		{
			name: "returns false after deletion",
			setup: func(ctx context.Context, srv *Server) {
				require.NoError(t, srv.ApplyGRPCBackend(ctx, "grpc-backend1", "default", []byte(`{}`)))
				require.NoError(t, srv.DeleteGRPCBackend(ctx, "grpc-backend1", "default"))
			},
			checkName: "grpc-backend1",
			checkNS:   "default",
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

			result := srv.HasGRPCBackend(tt.checkName, tt.checkNS)
			assert.Equal(t, tt.expected, result)
		})
	}
}

package proxy

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewConnectionPool(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()

	assert.NotNil(t, pool)
	assert.NotNil(t, pool.conns)
	assert.Equal(t, 0, pool.Size())
	assert.Equal(t, 10*time.Second, pool.timeout)
}

func TestNewConnectionPool_WithOptions(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	timeout := 30 * time.Second

	pool := NewConnectionPool(
		WithPoolLogger(logger),
		WithDialTimeout(timeout),
	)

	assert.NotNil(t, pool)
	assert.Equal(t, timeout, pool.timeout)
}

func TestNewConnectionPool_WithDialOptions(t *testing.T) {
	t.Parallel()

	opts := []grpc.DialOption{
		grpc.WithBlock(),
	}

	pool := NewConnectionPool(
		WithDialOptions(opts...),
	)

	assert.NotNil(t, pool)
	assert.NotEmpty(t, pool.dialOpts)
}

func TestConnectionPool_Get_NewConnection(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Get connection to a target (will create new)
	conn, err := pool.Get(ctx, "localhost:50051")
	require.NoError(t, err)
	assert.NotNil(t, conn)
	assert.Equal(t, 1, pool.Size())
}

func TestConnectionPool_Get_ExistingConnection(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Get first connection
	conn1, err := pool.Get(ctx, "localhost:50051")
	require.NoError(t, err)

	// Get same target again - should return same connection
	conn2, err := pool.Get(ctx, "localhost:50051")
	require.NoError(t, err)

	assert.Equal(t, conn1, conn2)
	assert.Equal(t, 1, pool.Size())
}

func TestConnectionPool_Get_MultipleTargets(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Get connections to different targets
	conn1, err := pool.Get(ctx, "localhost:50051")
	require.NoError(t, err)
	require.NotNil(t, conn1)

	conn2, err := pool.Get(ctx, "localhost:50052")
	require.NoError(t, err)
	require.NotNil(t, conn2)

	// Compare targets instead of connection objects to avoid race with gRPC internals
	assert.NotEqual(t, conn1.Target(), conn2.Target())
	assert.Equal(t, 2, pool.Size())
}

func TestConnectionPool_Close(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()

	ctx := context.Background()

	// Create some connections
	_, err := pool.Get(ctx, "localhost:50051")
	require.NoError(t, err)

	_, err = pool.Get(ctx, "localhost:50052")
	require.NoError(t, err)

	assert.Equal(t, 2, pool.Size())

	// Close pool
	err = pool.Close()
	require.NoError(t, err)

	assert.Equal(t, 0, pool.Size())
}

func TestConnectionPool_CloseConn(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Create connections
	_, err := pool.Get(ctx, "localhost:50051")
	require.NoError(t, err)

	_, err = pool.Get(ctx, "localhost:50052")
	require.NoError(t, err)

	assert.Equal(t, 2, pool.Size())

	// Close specific connection
	err = pool.CloseConn("localhost:50051")
	require.NoError(t, err)

	assert.Equal(t, 1, pool.Size())
}

func TestConnectionPool_CloseConn_NotExists(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	// Close non-existent connection - should not error
	err := pool.CloseConn("localhost:50051")
	require.NoError(t, err)
}

func TestConnectionPool_Size(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	assert.Equal(t, 0, pool.Size())

	_, _ = pool.Get(ctx, "localhost:50051")
	assert.Equal(t, 1, pool.Size())

	_, _ = pool.Get(ctx, "localhost:50052")
	assert.Equal(t, 2, pool.Size())
}

func TestConnectionPool_Targets(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Initially empty
	targets := pool.Targets()
	assert.Empty(t, targets)

	// Add connections
	_, _ = pool.Get(ctx, "localhost:50051")
	_, _ = pool.Get(ctx, "localhost:50052")

	targets = pool.Targets()
	assert.Len(t, targets, 2)
	assert.Contains(t, targets, "localhost:50051")
	assert.Contains(t, targets, "localhost:50052")
}

func TestConnectionPool_Concurrency(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Concurrent gets to same target
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			_, _ = pool.Get(ctx, "localhost:50051")
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	// Should only have one connection
	assert.Equal(t, 1, pool.Size())
}

func TestBuildDialOptions(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	opts := pool.buildDialOptions()

	assert.NotEmpty(t, opts)
	// Should have at least transport credentials and keepalive
	assert.GreaterOrEqual(t, len(opts), 2)
}

func TestWithPoolLogger(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	pool := &ConnectionPool{}

	opt := WithPoolLogger(logger)
	opt(pool)

	assert.NotNil(t, pool.logger)
}

func TestWithDialOptions(t *testing.T) {
	t.Parallel()

	pool := &ConnectionPool{}

	opt := WithDialOptions(grpc.WithBlock())
	opt(pool)

	assert.Len(t, pool.dialOpts, 1)
}

func TestWithDialTimeout(t *testing.T) {
	t.Parallel()

	pool := &ConnectionPool{}
	timeout := 30 * time.Second

	opt := WithDialTimeout(timeout)
	opt(pool)

	assert.Equal(t, timeout, pool.timeout)
}

func BenchmarkConnectionPool_Get_Existing(b *testing.B) {
	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Pre-create connection
	_, _ = pool.Get(ctx, "localhost:50051")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = pool.Get(ctx, "localhost:50051")
	}
}

func BenchmarkConnectionPool_Get_Concurrent(b *testing.B) {
	pool := NewConnectionPool()
	defer pool.Close()

	ctx := context.Background()

	// Pre-create connection
	_, _ = pool.Get(ctx, "localhost:50051")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = pool.Get(ctx, "localhost:50051")
		}
	})
}

func TestConnectionPool_IsTLSEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pool     *ConnectionPool
		expected bool
	}{
		{
			name:     "no TLS config",
			pool:     NewConnectionPool(),
			expected: false,
		},
		{
			name: "with TLS config",
			pool: NewConnectionPool(WithTLSConfig(&tls.Config{
				MinVersion: tls.VersionTLS12,
			})),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer tt.pool.Close()
			assert.Equal(t, tt.expected, tt.pool.IsTLSEnabled())
		})
	}
}

func TestConnectionPool_TLSConfig(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	pool := NewConnectionPool(WithTLSConfig(tlsConfig))
	defer pool.Close()

	assert.Equal(t, tlsConfig, pool.TLSConfig())
}

func TestConnectionPool_TLSConfig_Nil(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	assert.Nil(t, pool.TLSConfig())
}

func TestConnectionPool_SetTLSConfig(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool()
	defer pool.Close()

	// Initially no TLS
	assert.False(t, pool.IsTLSEnabled())

	// Set TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	pool.SetTLSConfig(tlsConfig)

	assert.True(t, pool.IsTLSEnabled())
	assert.Equal(t, tlsConfig, pool.TLSConfig())
}

func TestConnectionPool_SetTLSConfig_Nil(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	pool := NewConnectionPool(WithTLSConfig(tlsConfig))
	defer pool.Close()

	// Initially has TLS
	assert.True(t, pool.IsTLSEnabled())

	// Set nil TLS config
	pool.SetTLSConfig(nil)

	assert.False(t, pool.IsTLSEnabled())
	assert.Nil(t, pool.TLSConfig())
}

func TestWithTLSConfig(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	pool := &ConnectionPool{}
	opt := WithTLSConfig(tlsConfig)
	opt(pool)

	assert.Equal(t, tlsConfig, pool.tlsConfig)
}

func TestWithTLSFromConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cfg        *config.TLSConfig
		expectTLS  bool
		minVersion uint16
		expectALPN []string
	}{
		{
			name:      "nil config",
			cfg:       nil,
			expectTLS: false,
		},
		{
			name: "disabled config",
			cfg: &config.TLSConfig{
				Enabled: false,
			},
			expectTLS: false,
		},
		{
			name: "insecure mode config",
			cfg: &config.TLSConfig{
				Enabled: true,
				Mode:    "INSECURE",
			},
			expectTLS: false,
		},
		{
			name: "enabled TLS12",
			cfg: &config.TLSConfig{
				Enabled:    true,
				MinVersion: "TLS12",
			},
			expectTLS:  true,
			minVersion: tls.VersionTLS12,
			expectALPN: []string{"h2"},
		},
		{
			name: "enabled TLS13",
			cfg: &config.TLSConfig{
				Enabled:    true,
				MinVersion: "TLS13",
			},
			expectTLS:  true,
			minVersion: tls.VersionTLS13,
			expectALPN: []string{"h2"},
		},
		{
			name: "with custom ALPN",
			cfg: &config.TLSConfig{
				Enabled: true,
				ALPN:    []string{"h2", "http/1.1"},
			},
			expectTLS:  true,
			minVersion: tls.VersionTLS12,
			expectALPN: []string{"h2", "http/1.1"},
		},
		{
			name: "with insecure skip verify",
			cfg: &config.TLSConfig{
				Enabled:            true,
				InsecureSkipVerify: true,
			},
			expectTLS:  true,
			minVersion: tls.VersionTLS12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &ConnectionPool{}
			opt := WithTLSFromConfig(tt.cfg)
			opt(pool)

			if tt.expectTLS {
				assert.NotNil(t, pool.tlsConfig)
				assert.Equal(t, tt.minVersion, pool.tlsConfig.MinVersion)
				if tt.expectALPN != nil {
					assert.Equal(t, tt.expectALPN, pool.tlsConfig.NextProtos)
				}
			} else {
				assert.Nil(t, pool.tlsConfig)
			}
		})
	}
}

func TestConnectionPool_BuildDialOptions_WithTLS(t *testing.T) {
	t.Parallel()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	pool := NewConnectionPool(WithTLSConfig(tlsConfig))
	defer pool.Close()

	opts := pool.buildDialOptions()
	assert.NotEmpty(t, opts)
}

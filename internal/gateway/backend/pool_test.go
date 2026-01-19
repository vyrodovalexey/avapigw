package backend

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test Cases for NewConnectionPool
// ============================================================================

func TestNewConnectionPool(t *testing.T) {
	tests := []struct {
		name   string
		config *ConnectionPoolConfig
	}{
		{
			name: "creates pool with config",
			config: &ConnectionPoolConfig{
				MaxConnections:        100,
				MaxIdleConnections:    50,
				MaxConnectionsPerHost: 20,
				IdleTimeout:           120,
			},
		},
		{
			name:   "creates pool with nil config (uses defaults)",
			config: nil,
		},
		{
			name: "creates pool with minimal config",
			config: &ConnectionPoolConfig{
				MaxConnections:        10,
				MaxIdleConnections:    5,
				MaxConnectionsPerHost: 2,
				IdleTimeout:           30,
			},
		},
		{
			name: "creates pool with large values",
			config: &ConnectionPoolConfig{
				MaxConnections:        10000,
				MaxIdleConnections:    5000,
				MaxConnectionsPerHost: 1000,
				IdleTimeout:           3600,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewConnectionPool(tt.config)

			require.NotNil(t, pool)
			assert.NotNil(t, pool.transport)
			assert.NotNil(t, pool.config)
			assert.False(t, pool.IsClosed())

			// Verify config values
			if tt.config != nil {
				assert.Equal(t, tt.config.MaxIdleConnections, pool.config.MaxIdleConnections)
				assert.Equal(t, tt.config.MaxConnectionsPerHost, pool.config.MaxConnectionsPerHost)
				assert.Equal(t, tt.config.IdleTimeout, pool.config.IdleTimeout)
			} else {
				// Default values
				assert.Equal(t, 100, pool.config.MaxConnections)
				assert.Equal(t, 10, pool.config.MaxIdleConnections)
				assert.Equal(t, 10, pool.config.MaxConnectionsPerHost)
				assert.Equal(t, 90, pool.config.IdleTimeout)
			}
		})
	}
}

func TestNewConnectionPool_TransportSettings(t *testing.T) {
	config := &ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	}

	pool := NewConnectionPool(config)

	require.NotNil(t, pool)
	require.NotNil(t, pool.transport)

	// Verify transport settings
	assert.Equal(t, config.MaxIdleConnections, pool.transport.MaxIdleConns)
	assert.Equal(t, config.MaxConnectionsPerHost, pool.transport.MaxIdleConnsPerHost)
	assert.Equal(t, config.MaxConnectionsPerHost, pool.transport.MaxConnsPerHost)
	assert.Equal(t, time.Duration(config.IdleTimeout)*time.Second, pool.transport.IdleConnTimeout)
	assert.True(t, pool.transport.ForceAttemptHTTP2)
}

// ============================================================================
// Test Cases for ConnectionPool.GetTransport
// ============================================================================

func TestConnectionPool_GetTransport(t *testing.T) {
	pool := NewConnectionPool(&ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	})

	transport := pool.GetTransport()

	require.NotNil(t, transport)
	assert.IsType(t, &http.Transport{}, transport)
}

func TestConnectionPool_GetTransport_ReturnsSameInstance(t *testing.T) {
	pool := NewConnectionPool(nil)

	transport1 := pool.GetTransport()
	transport2 := pool.GetTransport()

	assert.Same(t, transport1, transport2)
}

// ============================================================================
// Test Cases for ConnectionPool.Close
// ============================================================================

func TestConnectionPool_Close(t *testing.T) {
	pool := NewConnectionPool(nil)

	assert.False(t, pool.IsClosed())

	pool.Close()

	assert.True(t, pool.IsClosed())
}

func TestConnectionPool_Close_Idempotent(t *testing.T) {
	pool := NewConnectionPool(nil)

	// Multiple closes should not panic
	assert.NotPanics(t, func() {
		pool.Close()
		pool.Close()
		pool.Close()
	})

	assert.True(t, pool.IsClosed())
}

func TestConnectionPool_Close_ClosesIdleConnections(t *testing.T) {
	pool := NewConnectionPool(nil)

	// Get transport to ensure it's initialized
	transport := pool.GetTransport()
	require.NotNil(t, transport)

	pool.Close()

	assert.True(t, pool.IsClosed())
}

// ============================================================================
// Test Cases for ConnectionPool.IsClosed
// ============================================================================

func TestConnectionPool_IsClosed(t *testing.T) {
	tests := []struct {
		name     string
		close    bool
		expected bool
	}{
		{
			name:     "returns false when not closed",
			close:    false,
			expected: false,
		},
		{
			name:     "returns true when closed",
			close:    true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewConnectionPool(nil)

			if tt.close {
				pool.Close()
			}

			result := pool.IsClosed()

			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Test Cases for ConnectionPool.Stats
// ============================================================================

func TestConnectionPool_Stats(t *testing.T) {
	config := &ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	}

	pool := NewConnectionPool(config)

	stats := pool.Stats()

	assert.Equal(t, config.MaxIdleConnections, stats.MaxIdleConns)
	assert.Equal(t, config.MaxConnectionsPerHost, stats.MaxConnsPerHost)
	assert.Equal(t, config.IdleTimeout, stats.IdleTimeout)
	assert.Equal(t, config.MaxConnectionsPerHost, stats.MaxIdleConnsPerHost)
}

func TestConnectionPool_Stats_DefaultConfig(t *testing.T) {
	pool := NewConnectionPool(nil)

	stats := pool.Stats()

	// Default values
	assert.Equal(t, 10, stats.MaxIdleConns)
	assert.Equal(t, 10, stats.MaxConnsPerHost)
	assert.Equal(t, 90, stats.IdleTimeout)
	assert.Equal(t, 10, stats.MaxIdleConnsPerHost)
}

// ============================================================================
// Test Cases for ConnectionPool.UpdateConfig
// ============================================================================

func TestConnectionPool_UpdateConfig(t *testing.T) {
	initialConfig := &ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	}

	pool := NewConnectionPool(initialConfig)

	newConfig := &ConnectionPoolConfig{
		MaxConnections:        200,
		MaxIdleConnections:    100,
		MaxConnectionsPerHost: 40,
		IdleTimeout:           240,
	}

	pool.UpdateConfig(newConfig)

	// Verify config was updated
	assert.Equal(t, newConfig.MaxIdleConnections, pool.config.MaxIdleConnections)
	assert.Equal(t, newConfig.MaxConnectionsPerHost, pool.config.MaxConnectionsPerHost)
	assert.Equal(t, newConfig.IdleTimeout, pool.config.IdleTimeout)

	// Verify transport was updated
	assert.Equal(t, newConfig.MaxIdleConnections, pool.transport.MaxIdleConns)
	assert.Equal(t, newConfig.MaxConnectionsPerHost, pool.transport.MaxIdleConnsPerHost)
	assert.Equal(t, newConfig.MaxConnectionsPerHost, pool.transport.MaxConnsPerHost)
	assert.Equal(t, time.Duration(newConfig.IdleTimeout)*time.Second, pool.transport.IdleConnTimeout)
}

func TestConnectionPool_UpdateConfig_NilConfig(t *testing.T) {
	initialConfig := &ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	}

	pool := NewConnectionPool(initialConfig)

	// Update with nil should be a no-op
	pool.UpdateConfig(nil)

	// Verify config was not changed
	assert.Equal(t, initialConfig.MaxIdleConnections, pool.config.MaxIdleConnections)
	assert.Equal(t, initialConfig.MaxConnectionsPerHost, pool.config.MaxConnectionsPerHost)
	assert.Equal(t, initialConfig.IdleTimeout, pool.config.IdleTimeout)
}

// ============================================================================
// Test Cases for DefaultConnectionPool
// ============================================================================

func TestDefaultConnectionPool(t *testing.T) {
	pool := DefaultConnectionPool()

	require.NotNil(t, pool)
	assert.NotNil(t, pool.transport)
	assert.NotNil(t, pool.config)
	assert.False(t, pool.IsClosed())

	// Verify default values
	assert.Equal(t, 100, pool.config.MaxConnections)
	assert.Equal(t, 100, pool.config.MaxIdleConnections)
	assert.Equal(t, 10, pool.config.MaxConnectionsPerHost)
	assert.Equal(t, 90, pool.config.IdleTimeout)
}

// ============================================================================
// Test Cases for ConnectionPool.PooledClient
// ============================================================================

func TestConnectionPool_PooledClient(t *testing.T) {
	pool := NewConnectionPool(nil)

	timeout := 30 * time.Second
	client := pool.PooledClient(timeout)

	require.NotNil(t, client)
	assert.Equal(t, timeout, client.Timeout)
	assert.Equal(t, pool.GetTransport(), client.Transport)
}

func TestConnectionPool_PooledClient_DifferentTimeouts(t *testing.T) {
	pool := NewConnectionPool(nil)

	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{
			name:    "short timeout",
			timeout: 5 * time.Second,
		},
		{
			name:    "medium timeout",
			timeout: 30 * time.Second,
		},
		{
			name:    "long timeout",
			timeout: 120 * time.Second,
		},
		{
			name:    "zero timeout",
			timeout: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := pool.PooledClient(tt.timeout)

			require.NotNil(t, client)
			assert.Equal(t, tt.timeout, client.Timeout)
		})
	}
}

func TestConnectionPool_PooledClient_SharesTransport(t *testing.T) {
	pool := NewConnectionPool(nil)

	client1 := pool.PooledClient(10 * time.Second)
	client2 := pool.PooledClient(20 * time.Second)

	// Both clients should share the same transport
	assert.Same(t, client1.Transport, client2.Transport)
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

func TestConnectionPool_ConcurrentGetTransport(t *testing.T) {
	pool := NewConnectionPool(nil)

	var wg sync.WaitGroup
	numGoroutines := 100

	transports := make(chan *http.Transport, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			transport := pool.GetTransport()
			transports <- transport
		}()
	}

	wg.Wait()
	close(transports)

	// All transports should be the same instance
	var firstTransport *http.Transport
	for transport := range transports {
		if firstTransport == nil {
			firstTransport = transport
		}
		assert.Same(t, firstTransport, transport)
	}
}

func TestConnectionPool_ConcurrentClose(t *testing.T) {
	pool := NewConnectionPool(nil)

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.Close()
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})

	assert.True(t, pool.IsClosed())
}

func TestConnectionPool_ConcurrentStats(t *testing.T) {
	pool := NewConnectionPool(&ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	})

	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats := pool.Stats()
			assert.Equal(t, 50, stats.MaxIdleConns)
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestConnectionPool_ConcurrentUpdateConfig(t *testing.T) {
	pool := NewConnectionPool(nil)

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			config := &ConnectionPoolConfig{
				MaxConnections:        100 + idx,
				MaxIdleConnections:    50 + idx,
				MaxConnectionsPerHost: 20 + idx,
				IdleTimeout:           120 + idx,
			}
			pool.UpdateConfig(config)
		}(i)
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

func TestConnectionPool_ConcurrentPooledClient(t *testing.T) {
	pool := NewConnectionPool(nil)

	var wg sync.WaitGroup
	numGoroutines := 100

	clients := make(chan *http.Client, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			timeout := time.Duration(idx+1) * time.Second
			client := pool.PooledClient(timeout)
			clients <- client
		}(i)
	}

	wg.Wait()
	close(clients)

	// All clients should share the same transport
	var firstTransport http.RoundTripper
	for client := range clients {
		require.NotNil(t, client)
		if firstTransport == nil {
			firstTransport = client.Transport
		}
		assert.Same(t, firstTransport, client.Transport)
	}
}

func TestConnectionPool_ConcurrentMixedOperations(t *testing.T) {
	pool := NewConnectionPool(nil)

	var wg sync.WaitGroup
	numGoroutines := 50

	for i := 0; i < numGoroutines; i++ {
		wg.Add(4)

		// GetTransport
		go func() {
			defer wg.Done()
			_ = pool.GetTransport()
		}()

		// Stats
		go func() {
			defer wg.Done()
			_ = pool.Stats()
		}()

		// IsClosed
		go func() {
			defer wg.Done()
			_ = pool.IsClosed()
		}()

		// PooledClient
		go func() {
			defer wg.Done()
			_ = pool.PooledClient(10 * time.Second)
		}()
	}

	assert.NotPanics(t, func() {
		wg.Wait()
	})
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

func TestConnectionPool_ZeroValues(t *testing.T) {
	config := &ConnectionPoolConfig{
		MaxConnections:        0,
		MaxIdleConnections:    0,
		MaxConnectionsPerHost: 0,
		IdleTimeout:           0,
	}

	pool := NewConnectionPool(config)

	require.NotNil(t, pool)
	assert.NotNil(t, pool.transport)

	// Pool should still be functional
	transport := pool.GetTransport()
	assert.NotNil(t, transport)
}

func TestConnectionPool_NegativeValues(t *testing.T) {
	config := &ConnectionPoolConfig{
		MaxConnections:        -1,
		MaxIdleConnections:    -1,
		MaxConnectionsPerHost: -1,
		IdleTimeout:           -1,
	}

	pool := NewConnectionPool(config)

	require.NotNil(t, pool)
	// Pool should still be created, transport handles negative values
}

func TestConnectionPool_GetTransportAfterClose(t *testing.T) {
	pool := NewConnectionPool(nil)
	pool.Close()

	// GetTransport should still return the transport even after close
	transport := pool.GetTransport()
	assert.NotNil(t, transport)
}

func TestConnectionPool_StatsAfterClose(t *testing.T) {
	pool := NewConnectionPool(&ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    50,
		MaxConnectionsPerHost: 20,
		IdleTimeout:           120,
	})

	pool.Close()

	// Stats should still work after close
	stats := pool.Stats()
	assert.Equal(t, 50, stats.MaxIdleConns)
}

func TestConnectionPool_UpdateConfigAfterClose(t *testing.T) {
	pool := NewConnectionPool(nil)
	pool.Close()

	// UpdateConfig should still work after close
	newConfig := &ConnectionPoolConfig{
		MaxConnections:        200,
		MaxIdleConnections:    100,
		MaxConnectionsPerHost: 40,
		IdleTimeout:           240,
	}

	assert.NotPanics(t, func() {
		pool.UpdateConfig(newConfig)
	})
}

func TestConnectionPool_PooledClientAfterClose(t *testing.T) {
	pool := NewConnectionPool(nil)
	pool.Close()

	// PooledClient should still work after close
	client := pool.PooledClient(10 * time.Second)
	assert.NotNil(t, client)
}

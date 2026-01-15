package backend

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ConnectionPool manages HTTP connections to backend services.
type ConnectionPool struct {
	transport *http.Transport
	config    *ConnectionPoolConfig
	mu        sync.RWMutex
	closed    bool
}

// NewConnectionPool creates a new connection pool.
func NewConnectionPool(config *ConnectionPoolConfig) *ConnectionPool {
	if config == nil {
		config = &ConnectionPoolConfig{
			MaxConnections:        100,
			MaxIdleConnections:    10,
			MaxConnectionsPerHost: 10,
			IdleTimeout:           90,
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          config.MaxIdleConnections,
		MaxIdleConnsPerHost:   config.MaxConnectionsPerHost,
		MaxConnsPerHost:       config.MaxConnectionsPerHost,
		IdleConnTimeout:       time.Duration(config.IdleTimeout) * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	return &ConnectionPool{
		transport: transport,
		config:    config,
	}
}

// GetTransport returns the HTTP transport.
func (p *ConnectionPool) GetTransport() *http.Transport {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.transport
}

// Close closes all idle connections.
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}

	p.transport.CloseIdleConnections()
	p.closed = true
}

// IsClosed returns whether the pool is closed.
func (p *ConnectionPool) IsClosed() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.closed
}

// Stats returns connection pool statistics.
func (p *ConnectionPool) Stats() ConnectionPoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return ConnectionPoolStats{
		MaxIdleConns:        p.config.MaxIdleConnections,
		MaxConnsPerHost:     p.config.MaxConnectionsPerHost,
		IdleTimeout:         p.config.IdleTimeout,
		MaxIdleConnsPerHost: p.config.MaxConnectionsPerHost,
	}
}

// ConnectionPoolStats holds connection pool statistics.
type ConnectionPoolStats struct {
	MaxIdleConns        int
	MaxConnsPerHost     int
	IdleTimeout         int
	MaxIdleConnsPerHost int
}

// UpdateConfig updates the connection pool configuration.
func (p *ConnectionPool) UpdateConfig(config *ConnectionPoolConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if config == nil {
		return
	}

	p.config = config

	// Update transport settings
	p.transport.MaxIdleConns = config.MaxIdleConnections
	p.transport.MaxIdleConnsPerHost = config.MaxConnectionsPerHost
	p.transport.MaxConnsPerHost = config.MaxConnectionsPerHost
	p.transport.IdleConnTimeout = time.Duration(config.IdleTimeout) * time.Second
}

// DefaultConnectionPool returns a connection pool with default settings.
func DefaultConnectionPool() *ConnectionPool {
	return NewConnectionPool(&ConnectionPoolConfig{
		MaxConnections:        100,
		MaxIdleConnections:    100,
		MaxConnectionsPerHost: 10,
		IdleTimeout:           90,
	})
}

// PooledClient returns an HTTP client using this connection pool.
func (p *ConnectionPool) PooledClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: p.GetTransport(),
		Timeout:   timeout,
	}
}

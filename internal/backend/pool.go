package backend

import (
	"net"
	"net/http"
	"time"
)

// PoolConfig contains connection pool configuration.
type PoolConfig struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	DisableKeepAlives     bool
	DisableCompression    bool
}

// DefaultPoolConfig returns default pool configuration.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
	}
}

// ConnectionPool manages HTTP connections.
type ConnectionPool struct {
	config    PoolConfig
	transport *http.Transport
	client    *http.Client
}

// NewConnectionPool creates a new connection pool.
func NewConnectionPool(config PoolConfig) *ConnectionPool {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		DisableCompression:    config.DisableCompression,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   0, // No timeout at client level, use context
	}

	return &ConnectionPool{
		config:    config,
		transport: transport,
		client:    client,
	}
}

// Client returns the HTTP client.
func (p *ConnectionPool) Client() *http.Client {
	return p.client
}

// Transport returns the HTTP transport.
func (p *ConnectionPool) Transport() *http.Transport {
	return p.transport
}

// CloseIdleConnections closes idle connections.
func (p *ConnectionPool) CloseIdleConnections() {
	p.transport.CloseIdleConnections()
}

// Stats returns pool statistics.
type PoolStats struct {
	MaxIdleConns        int
	MaxIdleConnsPerHost int
	MaxConnsPerHost     int
}

// Stats returns the pool statistics.
func (p *ConnectionPool) Stats() PoolStats {
	return PoolStats{
		MaxIdleConns:        p.config.MaxIdleConns,
		MaxIdleConnsPerHost: p.config.MaxIdleConnsPerHost,
		MaxConnsPerHost:     p.config.MaxConnsPerHost,
	}
}

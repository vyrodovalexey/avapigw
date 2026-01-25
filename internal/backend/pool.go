package backend

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Connection pool default configuration constants.
const (
	// DefaultMaxIdleConns is the default maximum number of idle connections.
	DefaultMaxIdleConns = 100

	// DefaultMaxIdleConnsPerHost is the default maximum idle connections per host.
	DefaultMaxIdleConnsPerHost = 10

	// DefaultMaxConnsPerHost is the default maximum connections per host.
	DefaultMaxConnsPerHost = 100

	// DefaultIdleConnTimeout is the default idle connection timeout.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultResponseHeaderTimeout is the default response header timeout.
	DefaultResponseHeaderTimeout = 30 * time.Second

	// DefaultExpectContinueTimeout is the default expect continue timeout.
	DefaultExpectContinueTimeout = 1 * time.Second

	// DefaultDialTimeout is the default dial timeout.
	DefaultDialTimeout = 30 * time.Second

	// DefaultDialKeepAlive is the default dial keep-alive interval.
	DefaultDialKeepAlive = 30 * time.Second
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
	TLSConfig             *tls.Config
}

// DefaultPoolConfig returns default pool configuration.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		MaxConnsPerHost:       DefaultMaxConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		ExpectContinueTimeout: DefaultExpectContinueTimeout,
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
			Timeout:   DefaultDialTimeout,
			KeepAlive: DefaultDialKeepAlive,
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
		TLSClientConfig:       config.TLSConfig,
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

// NewConnectionPoolWithTLS creates a new connection pool with TLS configuration.
func NewConnectionPoolWithTLS(config PoolConfig, tlsConfig *tls.Config) *ConnectionPool {
	config.TLSConfig = tlsConfig
	return NewConnectionPool(config)
}

// SetTLSConfig updates the TLS configuration for the connection pool.
// Note: This closes existing idle connections.
func (p *ConnectionPool) SetTLSConfig(tlsConfig *tls.Config) {
	p.transport.TLSClientConfig = tlsConfig
	p.transport.CloseIdleConnections()
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

package backend

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultPoolConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultPoolConfig()

	assert.Equal(t, 100, cfg.MaxIdleConns)
	assert.Equal(t, 10, cfg.MaxIdleConnsPerHost)
	assert.Equal(t, 100, cfg.MaxConnsPerHost)
	assert.Equal(t, 90*time.Second, cfg.IdleConnTimeout)
	assert.Equal(t, 30*time.Second, cfg.ResponseHeaderTimeout)
	assert.Equal(t, 1*time.Second, cfg.ExpectContinueTimeout)
	assert.False(t, cfg.DisableKeepAlives)
	assert.False(t, cfg.DisableCompression)
}

func TestNewConnectionPool(t *testing.T) {
	t.Parallel()

	cfg := DefaultPoolConfig()
	pool := NewConnectionPool(cfg)

	assert.NotNil(t, pool)
	assert.NotNil(t, pool.transport)
	assert.NotNil(t, pool.client)
}

func TestConnectionPool_Client(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(DefaultPoolConfig())
	client := pool.Client()

	assert.NotNil(t, client)
	assert.Equal(t, pool.client, client)
}

func TestConnectionPool_Transport(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(DefaultPoolConfig())
	transport := pool.Transport()

	assert.NotNil(t, transport)
	assert.Equal(t, pool.transport, transport)
}

func TestConnectionPool_CloseIdleConnections(t *testing.T) {
	t.Parallel()

	pool := NewConnectionPool(DefaultPoolConfig())

	// Should not panic
	pool.CloseIdleConnections()
}

func TestConnectionPool_Stats(t *testing.T) {
	t.Parallel()

	cfg := PoolConfig{
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 5,
		MaxConnsPerHost:     25,
	}

	pool := NewConnectionPool(cfg)
	stats := pool.Stats()

	assert.Equal(t, 50, stats.MaxIdleConns)
	assert.Equal(t, 5, stats.MaxIdleConnsPerHost)
	assert.Equal(t, 25, stats.MaxConnsPerHost)
}

func TestConnectionPool_CustomConfig(t *testing.T) {
	t.Parallel()

	cfg := PoolConfig{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       200,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DisableKeepAlives:     true,
		DisableCompression:    true,
	}

	pool := NewConnectionPool(cfg)

	assert.NotNil(t, pool)
	assert.Equal(t, cfg.MaxIdleConns, pool.config.MaxIdleConns)
	assert.Equal(t, cfg.DisableKeepAlives, pool.config.DisableKeepAlives)
	assert.Equal(t, cfg.DisableCompression, pool.config.DisableCompression)
}

func TestPoolStats(t *testing.T) {
	t.Parallel()

	stats := PoolStats{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     100,
	}

	assert.Equal(t, 100, stats.MaxIdleConns)
	assert.Equal(t, 10, stats.MaxIdleConnsPerHost)
	assert.Equal(t, 100, stats.MaxConnsPerHost)
}

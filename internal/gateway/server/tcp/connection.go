// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ConnectionTracker tracks active TCP connections for metrics and graceful shutdown.
type ConnectionTracker struct {
	connections sync.Map
	maxConns    int
	connCount   int64
	logger      *zap.Logger
}

// TrackedConnection represents a tracked TCP connection with metadata.
type TrackedConnection struct {
	ID         string
	RemoteAddr string
	LocalAddr  string
	StartTime  time.Time
	BytesIn    int64
	BytesOut   int64
	conn       net.Conn
	mu         sync.RWMutex
}

// NewConnectionTracker creates a new connection tracker.
func NewConnectionTracker(maxConns int, logger *zap.Logger) *ConnectionTracker {
	if maxConns <= 0 {
		maxConns = 10000 // Default max connections
	}

	return &ConnectionTracker{
		maxConns: maxConns,
		logger:   logger,
	}
}

// Add adds a new connection to the tracker.
// Returns an error if the maximum number of connections is reached.
func (t *ConnectionTracker) Add(conn net.Conn) (*TrackedConnection, error) {
	count := atomic.LoadInt64(&t.connCount)
	if int(count) >= t.maxConns {
		return nil, fmt.Errorf("maximum connections reached: %d", t.maxConns)
	}

	tracked := &TrackedConnection{
		ID:         uuid.New().String(),
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		StartTime:  time.Now(),
		conn:       conn,
	}

	t.connections.Store(tracked.ID, tracked)
	atomic.AddInt64(&t.connCount, 1)

	t.logger.Debug("connection added",
		zap.String("id", tracked.ID),
		zap.String("remoteAddr", tracked.RemoteAddr),
		zap.String("localAddr", tracked.LocalAddr),
	)

	return tracked, nil
}

// Remove removes a connection from the tracker.
func (t *ConnectionTracker) Remove(id string) {
	if _, loaded := t.connections.LoadAndDelete(id); loaded {
		atomic.AddInt64(&t.connCount, -1)
		t.logger.Debug("connection removed", zap.String("id", id))
	}
}

// Get returns a tracked connection by ID.
func (t *ConnectionTracker) Get(id string) *TrackedConnection {
	if v, ok := t.connections.Load(id); ok {
		return v.(*TrackedConnection)
	}
	return nil
}

// Count returns the current number of active connections.
func (t *ConnectionTracker) Count() int {
	return int(atomic.LoadInt64(&t.connCount))
}

// List returns all tracked connections.
func (t *ConnectionTracker) List() []*TrackedConnection {
	var connections []*TrackedConnection
	t.connections.Range(func(key, value interface{}) bool {
		connections = append(connections, value.(*TrackedConnection))
		return true
	})
	return connections
}

// CloseAll closes all tracked connections.
func (t *ConnectionTracker) CloseAll() {
	t.connections.Range(func(key, value interface{}) bool {
		tracked := value.(*TrackedConnection)
		if tracked.conn != nil {
			if err := tracked.conn.Close(); err != nil {
				t.logger.Debug("error closing connection",
					zap.String("id", tracked.ID),
					zap.Error(err),
				)
			}
		}
		return true
	})
}

// AddBytesIn adds to the bytes received counter for a connection.
func (tc *TrackedConnection) AddBytesIn(n int64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.BytesIn += n
}

// AddBytesOut adds to the bytes sent counter for a connection.
func (tc *TrackedConnection) AddBytesOut(n int64) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.BytesOut += n
}

// GetStats returns the current stats for the connection.
func (tc *TrackedConnection) GetStats() (bytesIn, bytesOut int64, duration time.Duration) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.BytesIn, tc.BytesOut, time.Since(tc.StartTime)
}

// Close closes the underlying connection.
func (tc *TrackedConnection) Close() error {
	if tc.conn != nil {
		return tc.conn.Close()
	}
	return nil
}

// CountingConn wraps a net.Conn to count bytes transferred.
type CountingConn struct {
	net.Conn
	tracked *TrackedConnection
}

// NewCountingConn creates a new counting connection wrapper.
func NewCountingConn(conn net.Conn, tracked *TrackedConnection) *CountingConn {
	return &CountingConn{
		Conn:    conn,
		tracked: tracked,
	}
}

// Read reads data from the connection and updates the bytes counter.
func (c *CountingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 && c.tracked != nil {
		c.tracked.AddBytesIn(int64(n))
	}
	return n, err
}

// Write writes data to the connection and updates the bytes counter.
func (c *CountingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 && c.tracked != nil {
		c.tracked.AddBytesOut(int64(n))
	}
	return n, err
}

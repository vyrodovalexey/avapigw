package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ConnectionPool manages gRPC client connections.
type ConnectionPool struct {
	conns    map[string]*grpc.ClientConn
	mu       sync.RWMutex
	dialOpts []grpc.DialOption
	logger   observability.Logger
	timeout  time.Duration
}

// PoolOption is a functional option for configuring the connection pool.
type PoolOption func(*ConnectionPool)

// WithPoolLogger sets the logger for the connection pool.
func WithPoolLogger(logger observability.Logger) PoolOption {
	return func(p *ConnectionPool) {
		p.logger = logger
	}
}

// WithDialOptions sets the dial options for the connection pool.
func WithDialOptions(opts ...grpc.DialOption) PoolOption {
	return func(p *ConnectionPool) {
		p.dialOpts = append(p.dialOpts, opts...)
	}
}

// WithDialTimeout sets the dial timeout for the connection pool.
func WithDialTimeout(timeout time.Duration) PoolOption {
	return func(p *ConnectionPool) {
		p.timeout = timeout
	}
}

// NewConnectionPool creates a new connection pool.
func NewConnectionPool(opts ...PoolOption) *ConnectionPool {
	p := &ConnectionPool{
		conns:   make(map[string]*grpc.ClientConn),
		logger:  observability.NopLogger(),
		timeout: 10 * time.Second,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Add default dial options if none provided
	if len(p.dialOpts) == 0 {
		p.dialOpts = defaultDialOptions()
	}

	return p
}

// defaultDialOptions returns default gRPC dial options.
func defaultDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(&rawCodec{}),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
}

// Get returns a connection to the target, creating one if necessary.
func (p *ConnectionPool) Get(ctx context.Context, target string) (*grpc.ClientConn, error) {
	// Try to get existing connection
	p.mu.RLock()
	conn, exists := p.conns[target]
	p.mu.RUnlock()

	if exists && conn != nil {
		// Check if connection is still usable
		state := conn.GetState()
		if state != 4 { // 4 = SHUTDOWN
			return conn, nil
		}
		// Connection is shutdown, remove it
		p.mu.Lock()
		delete(p.conns, target)
		p.mu.Unlock()
	}

	// Create new connection
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	conn, exists = p.conns[target]
	if exists && conn != nil {
		state := conn.GetState()
		if state != 4 {
			return conn, nil
		}
	}

	p.logger.Debug("creating new gRPC connection",
		observability.String("target", target),
	)

	// Use grpc.NewClient (non-blocking) instead of deprecated DialContext
	conn, err := grpc.NewClient(target, p.dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for %s: %w", target, err)
	}

	p.conns[target] = conn

	p.logger.Info("created gRPC connection",
		observability.String("target", target),
	)

	return conn, nil
}

// Close closes all connections in the pool.
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for target, conn := range p.conns {
		if err := conn.Close(); err != nil {
			p.logger.Error("failed to close connection",
				observability.String("target", target),
				observability.Error(err),
			)
			lastErr = err
		}
	}

	p.conns = make(map[string]*grpc.ClientConn)
	return lastErr
}

// CloseConn closes a specific connection.
func (p *ConnectionPool) CloseConn(target string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	conn, exists := p.conns[target]
	if !exists {
		return nil
	}

	delete(p.conns, target)
	return conn.Close()
}

// Size returns the number of connections in the pool.
func (p *ConnectionPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}

// Targets returns all targets in the pool.
func (p *ConnectionPool) Targets() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	targets := make([]string, 0, len(p.conns))
	for target := range p.conns {
		targets = append(targets, target)
	}
	return targets
}

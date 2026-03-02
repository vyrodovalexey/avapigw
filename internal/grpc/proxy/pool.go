package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// ConnectionPool manages gRPC client connections.
type ConnectionPool struct {
	conns      map[string]*grpc.ClientConn
	mu         sync.RWMutex
	dialOpts   []grpc.DialOption
	logger     observability.Logger
	timeout    time.Duration
	tlsConfig  *tls.Config
	tlsConfigs map[string]*tls.Config // per-target TLS configs for mTLS backends
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

// WithTLSConfig sets the TLS configuration for the connection pool.
func WithTLSConfig(tlsConfig *tls.Config) PoolOption {
	return func(p *ConnectionPool) {
		p.tlsConfig = tlsConfig
	}
}

// WithTLSFromConfig creates TLS configuration from config.TLSConfig.
func WithTLSFromConfig(cfg *config.TLSConfig) PoolOption {
	return func(p *ConnectionPool) {
		if cfg == nil || !cfg.Enabled || cfg.IsInsecure() {
			return
		}

		tlsConfig := &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // Intentional for dev/testing
		}

		// Set minimum TLS version
		switch cfg.GetEffectiveMinVersion() {
		case "TLS12":
			tlsConfig.MinVersion = tls.VersionTLS12
		case "TLS13":
			tlsConfig.MinVersion = tls.VersionTLS13
		default:
			tlsConfig.MinVersion = tls.VersionTLS12
		}

		// Set ALPN protocols (default to h2 for gRPC)
		if len(cfg.GetEffectiveALPN()) > 0 {
			tlsConfig.NextProtos = cfg.GetEffectiveALPN()
		} else {
			tlsConfig.NextProtos = []string{"h2"}
		}

		p.tlsConfig = tlsConfig
	}
}

// NewConnectionPool creates a new connection pool.
func NewConnectionPool(opts ...PoolOption) *ConnectionPool {
	p := &ConnectionPool{
		conns:      make(map[string]*grpc.ClientConn),
		logger:     observability.NopLogger(),
		timeout:    10 * time.Second,
		tlsConfigs: make(map[string]*tls.Config),
	}

	for _, opt := range opts {
		opt(p)
	}

	// Add default dial options if none provided
	if len(p.dialOpts) == 0 {
		p.dialOpts = p.buildDialOptions()
	}

	return p
}

// buildDialOptions builds dial options based on pool configuration.
func (p *ConnectionPool) buildDialOptions() []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(&rawCodec{}),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	// Add TLS credentials if configured
	if p.tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(p.tlsConfig)))
		p.logger.Debug("using TLS credentials for gRPC connections")
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts
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

	metrics := getGRPCProxyMetrics()

	// Use grpc.NewClient (non-blocking) instead of deprecated DialContext
	conn, err := grpc.NewClient(target, p.dialOpts...)
	if err != nil {
		metrics.connectionErrors.WithLabelValues(target, "dial").Inc()
		return nil, fmt.Errorf("failed to create client for %s: %w", target, err)
	}

	p.conns[target] = conn
	metrics.connectionCreated.WithLabelValues(target).Inc()
	metrics.poolSize.Set(float64(len(p.conns)))

	p.logger.Info("created gRPC connection",
		observability.String("target", target),
	)

	return conn, nil
}

// GetWithTLS returns a connection to the target using a specific TLS config.
// If tlsConfig is nil, it delegates to the standard Get method.
// If the target already has a connection with a different TLS config,
// the old connection is closed and a new one is created.
func (p *ConnectionPool) GetWithTLS(
	ctx context.Context, target string, tlsConfig *tls.Config,
) (*grpc.ClientConn, error) {
	if tlsConfig == nil {
		return p.Get(ctx, target)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if we already have a connection with the same TLS config
	existingTLS, hasTLS := p.tlsConfigs[target]
	conn, hasConn := p.conns[target]

	if hasConn && conn != nil && hasTLS && existingTLS == tlsConfig {
		state := conn.GetState()
		if state != 4 { // 4 = SHUTDOWN
			return conn, nil
		}
	}

	// Close existing connection if TLS config changed
	if hasConn && conn != nil {
		_ = conn.Close()
		delete(p.conns, target)
		p.logger.Debug("closed existing connection for TLS config change",
			observability.String("target", target),
		)
	}

	// Build dial options with the specific TLS config
	dialOpts := p.buildDialOptionsWithTLS(tlsConfig)

	p.logger.Debug("creating new gRPC connection with per-backend TLS",
		observability.String("target", target),
	)

	metrics := getGRPCProxyMetrics()

	newConn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		metrics.connectionErrors.WithLabelValues(target, "dial_tls").Inc()
		return nil, fmt.Errorf("failed to create TLS client for %s: %w", target, err)
	}

	p.conns[target] = newConn
	p.tlsConfigs[target] = tlsConfig
	metrics.connectionCreated.WithLabelValues(target).Inc()
	metrics.poolSize.Set(float64(len(p.conns)))

	p.logger.Info("created gRPC connection with per-backend TLS",
		observability.String("target", target),
	)

	return newConn, nil
}

// buildDialOptionsWithTLS builds dial options with a specific TLS config.
func (p *ConnectionPool) buildDialOptionsWithTLS(tlsConfig *tls.Config) []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.ForceCodec(&rawCodec{}),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	}
}

// Close closes all connections in the pool.
func (p *ConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	metrics := getGRPCProxyMetrics()
	var lastErr error
	for target, conn := range p.conns {
		if err := conn.Close(); err != nil {
			p.logger.Error("failed to close connection",
				observability.String("target", target),
				observability.Error(err),
			)
			lastErr = err
		}
		metrics.connectionClosed.WithLabelValues(target).Inc()
	}

	p.conns = make(map[string]*grpc.ClientConn)
	p.tlsConfigs = make(map[string]*tls.Config)
	metrics.poolSize.Set(0)
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
	delete(p.tlsConfigs, target)
	metrics := getGRPCProxyMetrics()
	metrics.connectionClosed.WithLabelValues(target).Inc()
	metrics.poolSize.Set(float64(len(p.conns)))
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

// IsTLSEnabled returns true if TLS is enabled for this pool.
func (p *ConnectionPool) IsTLSEnabled() bool {
	return p.tlsConfig != nil
}

// TLSConfig returns the TLS configuration for this pool.
func (p *ConnectionPool) TLSConfig() *tls.Config {
	return p.tlsConfig
}

// SetTLSConfig updates the TLS configuration and rebuilds dial options.
// Note: This does not affect existing connections.
func (p *ConnectionPool) SetTLSConfig(tlsConfig *tls.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.tlsConfig = tlsConfig
	p.dialOpts = p.buildDialOptions()

	p.logger.Info("updated TLS configuration for gRPC connection pool",
		observability.Bool("tlsEnabled", tlsConfig != nil),
	)
}

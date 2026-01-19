package backend

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCProxy handles proxying gRPC requests to backend services.
type GRPCProxy struct {
	manager     *Manager
	connections map[string]*grpc.ClientConn
	mu          sync.RWMutex
	logger      *zap.Logger
	config      *GRPCProxyConfig
}

// GRPCProxyConfig holds configuration for the gRPC proxy.
type GRPCProxyConfig struct {
	// MaxRecvMsgSize is the maximum message size in bytes the client can receive.
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum message size in bytes the client can send.
	MaxSendMsgSize int

	// DialTimeout is the timeout for establishing connections.
	DialTimeout time.Duration

	// TLS is the TLS configuration for backend connections.
	TLS *tls.Config

	// EnableRetry enables automatic retry for failed requests.
	EnableRetry bool

	// MaxRetries is the maximum number of retries.
	MaxRetries int

	// RetryBackoff is the backoff duration between retries.
	RetryBackoff time.Duration
}

// DefaultGRPCProxyConfig returns a GRPCProxyConfig with default values.
func DefaultGRPCProxyConfig() *GRPCProxyConfig {
	return &GRPCProxyConfig{
		MaxRecvMsgSize: 4 * 1024 * 1024, // 4 MB
		MaxSendMsgSize: 4 * 1024 * 1024, // 4 MB
		DialTimeout:    10 * time.Second,
		EnableRetry:    true,
		MaxRetries:     3,
		RetryBackoff:   100 * time.Millisecond,
	}
}

// NewGRPCProxy creates a new gRPC proxy.
func NewGRPCProxy(manager *Manager, logger *zap.Logger) *GRPCProxy {
	return NewGRPCProxyWithConfig(manager, logger, DefaultGRPCProxyConfig())
}

// NewGRPCProxyWithConfig creates a new gRPC proxy with custom configuration.
func NewGRPCProxyWithConfig(manager *Manager, logger *zap.Logger, config *GRPCProxyConfig) *GRPCProxy {
	if config == nil {
		config = DefaultGRPCProxyConfig()
	}
	return &GRPCProxy{
		manager:     manager,
		connections: make(map[string]*grpc.ClientConn),
		logger:      logger,
		config:      config,
	}
}

// GetConnection returns a gRPC client connection to the backend.
func (p *GRPCProxy) GetConnection(ctx context.Context, backend *Backend) (*grpc.ClientConn, error) {
	if backend == nil {
		return nil, fmt.Errorf("backend is nil")
	}

	key := fmt.Sprintf("%s/%s", backend.Namespace, backend.Name)

	// Check for existing connection
	p.mu.RLock()
	conn, exists := p.connections[key]
	p.mu.RUnlock()

	if exists && conn.GetState().String() != "SHUTDOWN" {
		return conn, nil
	}

	// Create new connection
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if conn, exists := p.connections[key]; exists && conn.GetState().String() != "SHUTDOWN" {
		return conn, nil
	}

	// Get a healthy endpoint
	endpoint := backend.GetHealthyEndpoint()
	if endpoint == nil {
		return nil, fmt.Errorf("no healthy endpoints available for backend %s", key)
	}

	// Build dial options
	opts := p.buildDialOptions()

	// Create the gRPC client connection
	target := endpoint.FullAddress()
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for backend %s: %w", target, err)
	}

	p.connections[key] = conn
	p.logger.Debug("created gRPC connection to backend",
		zap.String("backend", key),
		zap.String("target", target),
	)

	return conn, nil
}

// buildDialOptions builds the gRPC dial options.
func (p *GRPCProxy) buildDialOptions() []grpc.DialOption {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(p.config.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(p.config.MaxSendMsgSize),
		),
	}

	// Add TLS credentials if configured
	if p.config.TLS != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(p.config.TLS)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts
}

// ProxyUnary proxies a unary RPC call to the backend.
func (p *GRPCProxy) ProxyUnary(ctx context.Context, fullMethod string, req []byte, backend *Backend) ([]byte, error) {
	conn, err := p.GetConnection(ctx, backend)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to get connection: %v", err)
	}

	// Create a raw frame for the request
	frame := &rawFrame{data: req}

	// Invoke the method
	var respFrame rawFrame

	err = conn.Invoke(ctx, fullMethod, frame, &respFrame, grpc.ForceCodec(&rawCodec{}))
	if err != nil {
		p.logger.Debug("proxy unary call failed",
			zap.String("method", fullMethod),
			zap.Error(err),
		)
		return nil, err
	}

	return respFrame.data, nil
}

// ProxyStream proxies a streaming RPC call to the backend.
func (p *GRPCProxy) ProxyStream(
	ctx context.Context,
	desc *grpc.StreamDesc,
	fullMethod string,
	backend *Backend,
) (grpc.ClientStream, error) {
	conn, err := p.GetConnection(ctx, backend)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to get connection: %v", err)
	}

	// Get incoming metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	// Create client stream
	stream, err := conn.NewStream(ctx, desc, fullMethod, grpc.ForceCodec(&rawCodec{}))
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "failed to create stream: %v", err)
	}

	return stream, nil
}

// ProxyBidirectionalStream proxies a bidirectional streaming RPC call.
func (p *GRPCProxy) ProxyBidirectionalStream(
	ctx context.Context,
	fullMethod string,
	backend *Backend,
	serverStream grpc.ServerStream,
) error {
	conn, err := p.GetConnection(ctx, backend)
	if err != nil {
		return status.Errorf(codes.Unavailable, "failed to get connection: %v", err)
	}

	// Get incoming metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	// Create client stream
	desc := &grpc.StreamDesc{
		ServerStreams: true,
		ClientStreams: true,
	}

	clientStream, err := conn.NewStream(ctx, desc, fullMethod, grpc.ForceCodec(&rawCodec{}))
	if err != nil {
		return status.Errorf(codes.Unavailable, "failed to create stream: %v", err)
	}

	// Bidirectional streaming
	errChan := make(chan error, 2)

	// Forward client -> backend
	go func() {
		errChan <- p.forwardClientToBackend(serverStream, clientStream)
	}()

	// Forward backend -> client
	go func() {
		errChan <- p.forwardBackendToClient(clientStream, serverStream)
	}()

	// Wait for both directions to complete
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil && err != io.EOF {
			return err
		}
	}

	return nil
}

// forwardClientToBackend forwards messages from client to backend.
func (p *GRPCProxy) forwardClientToBackend(src grpc.ServerStream, dst grpc.ClientStream) error {
	for {
		var frame rawFrame
		if err := src.RecvMsg(&frame); err != nil {
			if err == io.EOF {
				return dst.CloseSend()
			}
			return err
		}

		if err := dst.SendMsg(&frame); err != nil {
			return err
		}
	}
}

// forwardBackendToClient forwards messages from backend to client.
func (p *GRPCProxy) forwardBackendToClient(src grpc.ClientStream, dst grpc.ServerStream) error {
	// Forward headers
	header, err := src.Header()
	if err != nil {
		return err
	}
	if err := dst.SendHeader(header); err != nil {
		return err
	}

	for {
		var frame rawFrame
		if err := src.RecvMsg(&frame); err != nil {
			if err == io.EOF {
				dst.SetTrailer(src.Trailer())
				return nil
			}
			return err
		}

		if err := dst.SendMsg(&frame); err != nil {
			return err
		}
	}
}

// Close closes all connections.
func (p *GRPCProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var lastErr error
	for key, conn := range p.connections {
		if err := conn.Close(); err != nil {
			p.logger.Error("failed to close connection",
				zap.String("key", key),
				zap.Error(err),
			)
			lastErr = err
		}
	}

	p.connections = make(map[string]*grpc.ClientConn)
	return lastErr
}

// rawFrame represents a raw gRPC message frame.
type rawFrame struct {
	data []byte
}

// rawCodec is a codec that passes through raw bytes without marshaling.
type rawCodec struct{}

// Marshal implements the encoding.Codec interface.
func (c *rawCodec) Marshal(v interface{}) ([]byte, error) {
	switch msg := v.(type) {
	case *rawFrame:
		return msg.data, nil
	case []byte:
		return msg, nil
	default:
		return nil, fmt.Errorf("rawCodec: unsupported type %T", v)
	}
}

// Unmarshal implements the encoding.Codec interface.
func (c *rawCodec) Unmarshal(data []byte, v interface{}) error {
	switch msg := v.(type) {
	case *rawFrame:
		msg.data = data
		return nil
	case *[]byte:
		*msg = data
		return nil
	default:
		return fmt.Errorf("rawCodec: unsupported type %T", v)
	}
}

// Name returns the name of the codec.
func (c *rawCodec) Name() string {
	return "raw"
}

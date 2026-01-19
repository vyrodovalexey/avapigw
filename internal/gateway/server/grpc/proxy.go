package grpc

import (
	"context"
	"fmt"
	"io"
	"sync"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// Proxy handles proxying gRPC requests to backend services.
type Proxy struct {
	backendManager *backend.Manager
	connections    map[string]*grpc.ClientConn
	mu             sync.RWMutex
	logger         *zap.Logger
	config         *ProxyConfig
}

// ProxyConfig holds configuration for the proxy.
type ProxyConfig struct {
	// MaxRecvMsgSize is the maximum message size in bytes the client can receive.
	MaxRecvMsgSize int

	// MaxSendMsgSize is the maximum message size in bytes the client can send.
	MaxSendMsgSize int

	// EnableRetry enables automatic retry for failed requests.
	EnableRetry bool

	// MaxRetries is the maximum number of retries.
	MaxRetries int
}

// DefaultProxyConfig returns a ProxyConfig with default values.
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		MaxRecvMsgSize: 4 * 1024 * 1024, // 4 MB
		MaxSendMsgSize: 4 * 1024 * 1024, // 4 MB
		EnableRetry:    true,
		MaxRetries:     3,
	}
}

// NewProxy creates a new proxy.
func NewProxy(manager *backend.Manager, logger *zap.Logger) *Proxy {
	return &Proxy{
		backendManager: manager,
		connections:    make(map[string]*grpc.ClientConn),
		logger:         logger,
		config:         DefaultProxyConfig(),
	}
}

// NewProxyWithConfig creates a new proxy with custom configuration.
func NewProxyWithConfig(manager *backend.Manager, logger *zap.Logger, config *ProxyConfig) *Proxy {
	if config == nil {
		config = DefaultProxyConfig()
	}
	return &Proxy{
		backendManager: manager,
		connections:    make(map[string]*grpc.ClientConn),
		logger:         logger,
		config:         config,
	}
}

// GetConnection returns a gRPC client connection to the backend.
func (p *Proxy) GetConnection(ctx context.Context, backendRef *BackendRef) (*grpc.ClientConn, error) {
	if backendRef == nil {
		return nil, fmt.Errorf("backend reference is nil")
	}

	key := p.buildConnectionKey(backendRef)

	if conn := p.getExistingConnection(key); conn != nil {
		return conn, nil
	}

	return p.createNewConnection(backendRef, key)
}

// buildConnectionKey constructs the connection pool key from backend reference.
func (p *Proxy) buildConnectionKey(backendRef *BackendRef) string {
	return fmt.Sprintf("%s/%s:%d", backendRef.Namespace, backendRef.Name, backendRef.Port)
}

// getExistingConnection returns an existing valid connection if available.
func (p *Proxy) getExistingConnection(key string) *grpc.ClientConn {
	p.mu.RLock()
	conn, exists := p.connections[key]
	p.mu.RUnlock()

	if exists && conn.GetState().String() != "SHUTDOWN" {
		return conn
	}
	return nil
}

// createNewConnection creates a new gRPC connection to the backend.
func (p *Proxy) createNewConnection(backendRef *BackendRef, key string) (*grpc.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if conn, exists := p.connections[key]; exists && conn.GetState().String() != "SHUTDOWN" {
		return conn, nil
	}

	endpoint, backendKey, err := p.getBackendEndpoint(backendRef)
	if err != nil {
		return nil, err
	}

	conn, err := p.dialBackend(endpoint, backendKey)
	if err != nil {
		return nil, err
	}

	p.connections[key] = conn
	return conn, nil
}

// getBackendEndpoint retrieves a healthy endpoint from the backend manager.
func (p *Proxy) getBackendEndpoint(backendRef *BackendRef) (*backend.Endpoint, string, error) {
	backendKey := backendRef.Name
	if backendRef.Namespace != "" {
		backendKey = fmt.Sprintf("%s/%s", backendRef.Namespace, backendRef.Name)
	}

	be := p.backendManager.GetBackend(backendKey)
	if be == nil {
		return nil, "", fmt.Errorf("backend %s not found", backendKey)
	}

	endpoint := be.GetHealthyEndpoint()
	if endpoint == nil {
		return nil, "", fmt.Errorf("no healthy endpoints available for backend %s", backendKey)
	}

	return endpoint, backendKey, nil
}

// dialBackend creates a gRPC client connection to the endpoint.
func (p *Proxy) dialBackend(endpoint *backend.Endpoint, backendKey string) (*grpc.ClientConn, error) {
	opts := p.buildDialOptions()
	target := endpoint.FullAddress()

	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create client for backend %s: %w", target, err)
	}

	p.logger.Debug("created gRPC connection to backend",
		zap.String("backend", backendKey),
		zap.String("target", target),
	)

	return conn, nil
}

// buildDialOptions constructs the gRPC dial options.
func (p *Proxy) buildDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(p.config.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(p.config.MaxSendMsgSize),
		),
	}
}

// ProxyUnary proxies a unary RPC call to the backend.
func (p *Proxy) ProxyUnary(
	ctx context.Context,
	fullMethod string,
	req []byte,
	backendRef *BackendRef,
) ([]byte, metadata.MD, error) {
	conn, err := p.GetConnection(ctx, backendRef)
	if err != nil {
		return nil, nil, status.Errorf(codes.Unavailable, "failed to get connection: %v", err)
	}

	// Create a raw frame for the request
	frame := &RawFrame{Data: req}

	// Invoke the method
	var respFrame RawFrame
	var header, trailer metadata.MD

	err = conn.Invoke(ctx, fullMethod, frame, &respFrame,
		grpc.Header(&header),
		grpc.Trailer(&trailer),
		grpc.ForceCodec(&RawCodec{}),
	)

	if err != nil {
		p.logger.Debug("proxy unary call failed",
			zap.String("method", fullMethod),
			zap.Error(err),
		)
		return nil, nil, err
	}

	// Merge header and trailer
	respMD := metadata.Join(header, trailer)

	return respFrame.Data, respMD, nil
}

// ProxyStream proxies a streaming RPC call to the backend.
func (p *Proxy) ProxyStream(
	ctx context.Context,
	desc *grpc.StreamDesc,
	fullMethod string,
	backendRef *BackendRef,
	serverStream grpc.ServerStream,
) error {
	conn, err := p.GetConnection(ctx, backendRef)
	if err != nil {
		return status.Errorf(codes.Unavailable, "failed to get connection: %v", err)
	}

	// Get incoming metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	// Create client stream
	clientStream, err := conn.NewStream(ctx, desc, fullMethod, grpc.ForceCodec(&RawCodec{}))
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
func (p *Proxy) forwardClientToBackend(src grpc.ServerStream, dst grpc.ClientStream) error {
	for {
		var frame RawFrame
		if err := src.RecvMsg(&frame); err != nil {
			if err == io.EOF {
				// Close send on the client stream
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
func (p *Proxy) forwardBackendToClient(src grpc.ClientStream, dst grpc.ServerStream) error {
	// Forward headers
	header, err := src.Header()
	if err != nil {
		return err
	}
	if err := dst.SendHeader(header); err != nil {
		return err
	}

	for {
		var frame RawFrame
		if err := src.RecvMsg(&frame); err != nil {
			if err == io.EOF {
				// Set trailer
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

// TransparentHandler returns a handler for unknown services that proxies to backends.
func (p *Proxy) TransparentHandler(router *Router) grpc.StreamHandler {
	return func(srv interface{}, stream grpc.ServerStream) error {
		ctx := stream.Context()

		// Get the full method name from the context
		fullMethod, ok := grpc.Method(ctx)
		if !ok {
			return status.Error(codes.Internal, "failed to get method from context")
		}

		// Parse service and method from full method name
		service, method := parseFullMethod(fullMethod)

		// Get metadata
		md, _ := metadata.FromIncomingContext(ctx)

		// Match route
		route, rule := router.Match(service, method, md)
		if route == nil {
			p.logger.Debug("no route matched for gRPC request",
				zap.String("service", service),
				zap.String("method", method),
			)
			return status.Errorf(codes.Unimplemented, "unknown service %s", service)
		}

		// Get backend reference
		if len(rule.BackendRefs) == 0 {
			return status.Error(codes.Unavailable, "no backends configured for route")
		}

		// Use first backend (TODO: implement load balancing)
		backendRef := &rule.BackendRefs[0]

		p.logger.Debug("proxying gRPC request",
			zap.String("route", route.Name),
			zap.String("service", service),
			zap.String("method", method),
			zap.String("backend", backendRef.Name),
		)

		// Determine stream type
		desc := &grpc.StreamDesc{
			ServerStreams: true,
			ClientStreams: true,
		}

		return p.ProxyStream(ctx, desc, fullMethod, backendRef, stream)
	}
}

// Close closes all connections.
func (p *Proxy) Close() error {
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

// parseFullMethod parses the full method name into service and method.
// Full method format: /package.Service/Method
func parseFullMethod(fullMethod string) (service, method string) {
	if fullMethod == "" {
		return "", ""
	}

	// Remove leading slash
	if fullMethod[0] == '/' {
		fullMethod = fullMethod[1:]
	}

	// Find the last slash
	for i := len(fullMethod) - 1; i >= 0; i-- {
		if fullMethod[i] == '/' {
			return fullMethod[:i], fullMethod[i+1:]
		}
	}

	return fullMethod, ""
}

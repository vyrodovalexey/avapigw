// Package tcp provides the TCP server implementation for the API Gateway.
package tcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// Proxy handles TCP connection proxying to backend services.
type Proxy struct {
	backendManager *backend.Manager
	logger         *zap.Logger
	bufferPool     *sync.Pool
	bufferSize     int
}

// ProxyConfig holds configuration for the TCP proxy.
type ProxyConfig struct {
	BufferSize int
}

// DefaultProxyConfig returns default proxy configuration.
func DefaultProxyConfig() *ProxyConfig {
	return &ProxyConfig{
		BufferSize: 32 * 1024, // 32 KB buffer
	}
}

// NewProxy creates a new TCP proxy.
func NewProxy(manager *backend.Manager, logger *zap.Logger) *Proxy {
	return NewProxyWithConfig(manager, logger, DefaultProxyConfig())
}

// NewProxyWithConfig creates a new TCP proxy with custom configuration.
func NewProxyWithConfig(manager *backend.Manager, logger *zap.Logger, config *ProxyConfig) *Proxy {
	if config == nil {
		config = DefaultProxyConfig()
	}

	bufferSize := config.BufferSize
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}

	return &Proxy{
		backendManager: manager,
		logger:         logger,
		bufferSize:     bufferSize,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
	}
}

// Proxy proxies data between the client connection and a backend.
func (p *Proxy) Proxy(
	ctx context.Context,
	clientConn net.Conn,
	backendRef *backend.Backend,
	timeout time.Duration,
) error {
	if backendRef == nil {
		return fmt.Errorf("backend is nil")
	}

	// Get a healthy endpoint from the backend
	endpoint := backendRef.GetHealthyEndpoint()
	if endpoint == nil {
		return fmt.Errorf("no healthy endpoints available for backend %s", backendRef.Name)
	}

	// Connect to backend with timeout
	backendAddr := endpoint.FullAddress()
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, err)
	}
	defer backendConn.Close()

	p.logger.Debug("connected to backend",
		zap.String("backend", backendRef.Name),
		zap.String("address", backendAddr),
		zap.String("client", clientConn.RemoteAddr().String()),
	)

	// Proxy data bidirectionally
	return p.bidirectionalCopy(ctx, clientConn, backendConn)
}

// ProxyWithAddress proxies data between the client connection and a specific backend address.
func (p *Proxy) ProxyWithAddress(
	ctx context.Context,
	clientConn net.Conn,
	backendAddr string,
	timeout time.Duration,
) error {
	// Connect to backend with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, err)
	}
	defer backendConn.Close()

	p.logger.Debug("connected to backend",
		zap.String("address", backendAddr),
		zap.String("client", clientConn.RemoteAddr().String()),
	)

	// Proxy data bidirectionally
	return p.bidirectionalCopy(ctx, clientConn, backendConn)
}

// bidirectionalCopy copies data bidirectionally between two connections.
// It properly handles context cancellation and ensures both copy goroutines exit.
func (p *Proxy) bidirectionalCopy(ctx context.Context, conn1, conn2 net.Conn) error {
	errCh := make(chan error, 2)

	// Create a context that we can cancel to signal copy goroutines
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Copy from conn1 to conn2
	go func() {
		err := p.copyWithBufferAndContext(copyCtx, conn2, conn1)
		errCh <- err
	}()

	// Copy from conn2 to conn1
	go func() {
		err := p.copyWithBufferAndContext(copyCtx, conn1, conn2)
		errCh <- err
	}()

	// Wait for context cancellation or one direction to complete
	var firstErr error
	select {
	case <-ctx.Done():
		// Context cancelled, close both connections to unblock copy goroutines
		_ = conn1.Close() // Ignore error on cleanup
		_ = conn2.Close() // Ignore error on cleanup
		firstErr = ctx.Err()
	case firstErr = <-errCh:
		// One direction completed, close both connections to signal the other
		_ = conn1.Close() // Ignore error on cleanup
		_ = conn2.Close() // Ignore error on cleanup
	}

	// Cancel the copy context to signal any remaining goroutines
	cancel()

	// Wait for the other direction to complete
	<-errCh

	return firstErr
}

// copyWithBufferAndContext copies data from src to dst using a pooled buffer,
// respecting context cancellation.
func (p *Proxy) copyWithBufferAndContext(ctx context.Context, dst, src net.Conn) error {
	bufPtr := p.bufferPool.Get().(*[]byte)
	defer p.bufferPool.Put(bufPtr)
	buf := *bufPtr

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, shouldContinue, err := p.readWithDeadline(src, buf)
		if err != nil {
			return err
		}
		if shouldContinue {
			continue
		}

		if n > 0 {
			if err := p.writeWithDeadline(dst, buf[:n]); err != nil {
				return err
			}
		}
	}
}

// readWithDeadline reads from the connection with a deadline for context checking.
// Returns bytes read, whether to continue the loop, and any error.
func (p *Proxy) readWithDeadline(src net.Conn, buf []byte) (bytesRead int, shouldContinue bool, err error) {
	if err := src.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return 0, false, handleConnError(err)
	}

	n, err := src.Read(buf)
	if err != nil {
		cont, readErr := handleReadError(err)
		return 0, cont, readErr
	}

	return n, false, nil
}

// writeWithDeadline writes data to the connection with a deadline.
func (p *Proxy) writeWithDeadline(dst net.Conn, data []byte) error {
	if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return handleConnError(err)
	}

	_, err := dst.Write(data)
	if err != nil {
		return handleConnError(err)
	}

	return nil
}

// handleConnError processes connection errors, returning nil for closed connections.
func handleConnError(err error) error {
	if isClosedError(err) {
		return nil
	}
	return err
}

// handleReadError processes read errors, returning whether to continue and any error.
func handleReadError(err error) (shouldContinue bool, returnErr error) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true, nil // timeout, continue loop
	}
	if isClosedError(err) {
		return false, nil // closed, exit gracefully
	}
	return false, err // propagate error
}

// CopyWithTimeout copies data with idle timeout support.
func (p *Proxy) CopyWithTimeout(dst, src net.Conn, idleTimeout time.Duration) error {
	return p.CopyWithTimeoutAndContext(context.Background(), dst, src, idleTimeout)
}

// CopyWithTimeoutAndContext copies data with idle timeout support and context cancellation.
func (p *Proxy) CopyWithTimeoutAndContext(ctx context.Context, dst, src net.Conn, idleTimeout time.Duration) error {
	bufPtr := p.bufferPool.Get().(*[]byte)
	defer p.bufferPool.Put(bufPtr)
	buf := *bufPtr

	checkInterval := calculateCheckInterval(idleTimeout)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		n, shouldContinue, err := p.readWithTimeoutDeadline(src, buf, checkInterval)
		if err != nil {
			return err
		}
		if shouldContinue {
			continue
		}

		if n > 0 {
			if err := p.writeWithTimeoutDeadline(dst, buf[:n], idleTimeout); err != nil {
				return err
			}
		}
	}
}

// calculateCheckInterval returns the check interval for context cancellation.
// Uses a shorter interval to respond to context cancellation quickly.
func calculateCheckInterval(idleTimeout time.Duration) time.Duration {
	if idleTimeout > 1*time.Second {
		return 1 * time.Second
	}
	return idleTimeout
}

// readWithTimeoutDeadline reads from the connection with a configurable deadline.
// Returns bytes read, whether to continue the loop, and any error.
func (p *Proxy) readWithTimeoutDeadline(
	src net.Conn,
	buf []byte,
	deadline time.Duration,
) (bytesRead int, shouldContinue bool, err error) {
	if err := src.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return 0, false, handleConnError(err)
	}

	n, err := src.Read(buf)
	if err != nil {
		cont, readErr := handleReadErrorWithEOF(err)
		return 0, cont, readErr
	}

	return n, false, nil
}

// writeWithTimeoutDeadline writes data to the connection with a configurable deadline.
func (p *Proxy) writeWithTimeoutDeadline(dst net.Conn, data []byte, timeout time.Duration) error {
	if err := dst.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return handleConnError(err)
	}

	_, err := dst.Write(data)
	if err != nil {
		return handleConnError(err)
	}

	return nil
}

// handleReadErrorWithEOF processes read errors including EOF, returning whether to continue and any error.
func handleReadErrorWithEOF(err error) (shouldContinue bool, returnErr error) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true, nil // timeout, continue loop
	}
	if err == io.EOF {
		return false, nil // EOF, exit gracefully
	}
	if isClosedError(err) {
		return false, nil // closed, exit gracefully
	}
	return false, err // propagate error
}

// ProxyWithIdleTimeout proxies data with idle timeout support.
func (p *Proxy) ProxyWithIdleTimeout(
	ctx context.Context,
	clientConn net.Conn,
	backendRef *backend.Backend,
	connectTimeout, idleTimeout time.Duration,
) error {
	if backendRef == nil {
		return fmt.Errorf("backend is nil")
	}

	// Get a healthy endpoint from the backend
	endpoint := backendRef.GetHealthyEndpoint()
	if endpoint == nil {
		return fmt.Errorf("no healthy endpoints available for backend %s", backendRef.Name)
	}

	// Connect to backend with timeout
	backendAddr := endpoint.FullAddress()
	dialer := &net.Dialer{
		Timeout: connectTimeout,
	}

	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, err)
	}
	defer backendConn.Close()

	p.logger.Debug("connected to backend with idle timeout",
		zap.String("backend", backendRef.Name),
		zap.String("address", backendAddr),
		zap.String("client", clientConn.RemoteAddr().String()),
		zap.Duration("idleTimeout", idleTimeout),
	)

	// Proxy data bidirectionally with idle timeout
	return p.bidirectionalCopyWithTimeout(ctx, clientConn, backendConn, idleTimeout)
}

// bidirectionalCopyWithTimeout copies data bidirectionally with idle timeout.
// It properly handles context cancellation and ensures both copy goroutines exit.
func (p *Proxy) bidirectionalCopyWithTimeout(
	ctx context.Context,
	conn1, conn2 net.Conn,
	idleTimeout time.Duration,
) error {
	errCh := make(chan error, 2)

	// Create a context that we can cancel to signal copy goroutines
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Copy from conn1 to conn2
	go func() {
		errCh <- p.CopyWithTimeoutAndContext(copyCtx, conn2, conn1, idleTimeout)
	}()

	// Copy from conn2 to conn1
	go func() {
		errCh <- p.CopyWithTimeoutAndContext(copyCtx, conn1, conn2, idleTimeout)
	}()

	// Wait for context cancellation or one direction to complete
	var firstErr error
	select {
	case <-ctx.Done():
		// Context cancelled, close both connections to unblock copy goroutines
		_ = conn1.Close() // Ignore error on cleanup
		_ = conn2.Close() // Ignore error on cleanup
		firstErr = ctx.Err()
	case firstErr = <-errCh:
		// One direction completed, close both connections to signal the other
		_ = conn1.Close() // Ignore error on cleanup
		_ = conn2.Close() // Ignore error on cleanup
	}

	// Cancel the copy context to signal any remaining goroutines
	cancel()

	// Wait for the other direction to complete
	<-errCh

	return firstErr
}

// isClosedError checks if the error is due to a closed connection.
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	if netErr, ok := err.(*net.OpError); ok {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return false
}

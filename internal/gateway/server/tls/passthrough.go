// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
)

// PassthroughProxy handles TLS passthrough proxying.
// It forwards TLS connections to backends without terminating TLS.
type PassthroughProxy struct {
	backendManager *backend.Manager
	logger         *zap.Logger
	bufferPool     *sync.Pool
	bufferSize     int
}

// PassthroughProxyConfig holds configuration for the passthrough proxy.
type PassthroughProxyConfig struct {
	BufferSize int
}

// DefaultPassthroughProxyConfig returns default configuration.
func DefaultPassthroughProxyConfig() *PassthroughProxyConfig {
	return &PassthroughProxyConfig{
		BufferSize: 32 * 1024, // 32 KB
	}
}

// NewPassthroughProxy creates a new TLS passthrough proxy.
func NewPassthroughProxy(manager *backend.Manager, logger *zap.Logger) *PassthroughProxy {
	return NewPassthroughProxyWithConfig(manager, logger, DefaultPassthroughProxyConfig())
}

// NewPassthroughProxyWithConfig creates a new TLS passthrough proxy with custom configuration.
func NewPassthroughProxyWithConfig(
	manager *backend.Manager,
	logger *zap.Logger,
	config *PassthroughProxyConfig,
) *PassthroughProxy {
	if config == nil {
		config = DefaultPassthroughProxyConfig()
	}

	bufferSize := config.BufferSize
	if bufferSize <= 0 {
		bufferSize = 32 * 1024
	}

	return &PassthroughProxy{
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

// Proxy proxies a TLS connection to a backend without terminating TLS.
// The clientHello parameter contains the already-read ClientHello bytes that need to be
// forwarded to the backend.
func (p *PassthroughProxy) Proxy(
	ctx context.Context,
	clientConn net.Conn,
	clientHello []byte,
	backendRef *backend.Backend,
) error {
	if backendRef == nil {
		return fmt.Errorf("backend is nil")
	}

	// Get a healthy endpoint from the backend
	endpoint := backendRef.GetHealthyEndpoint()
	if endpoint == nil {
		return fmt.Errorf("no healthy endpoints available for backend %s", backendRef.Name)
	}

	// Connect to backend
	backendAddr := endpoint.FullAddress()
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}

	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, err)
	}
	defer backendConn.Close()

	p.logger.Debug("TLS passthrough connected to backend",
		zap.String("backend", backendRef.Name),
		zap.String("address", backendAddr),
		zap.String("client", clientConn.RemoteAddr().String()),
	)

	// Forward the ClientHello to the backend
	if len(clientHello) > 0 {
		if _, err := backendConn.Write(clientHello); err != nil {
			return fmt.Errorf("failed to forward ClientHello: %w", err)
		}
	}

	// Proxy data bidirectionally
	return p.bidirectionalCopy(ctx, clientConn, backendConn)
}

// ProxyWithAddress proxies a TLS connection to a specific backend address.
func (p *PassthroughProxy) ProxyWithAddress(
	ctx context.Context,
	clientConn net.Conn,
	clientHello []byte,
	backendAddr string,
	timeout time.Duration,
) error {
	// Connect to backend
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, err)
	}
	defer backendConn.Close()

	p.logger.Debug("TLS passthrough connected to backend",
		zap.String("address", backendAddr),
		zap.String("client", clientConn.RemoteAddr().String()),
	)

	// Forward the ClientHello to the backend
	if len(clientHello) > 0 {
		if _, err := backendConn.Write(clientHello); err != nil {
			return fmt.Errorf("failed to forward ClientHello: %w", err)
		}
	}

	// Proxy data bidirectionally
	return p.bidirectionalCopy(ctx, clientConn, backendConn)
}

// bidirectionalCopy copies data bidirectionally between two connections.
// It properly handles context cancellation and ensures both copy goroutines exit.
func (p *PassthroughProxy) bidirectionalCopy(ctx context.Context, conn1, conn2 net.Conn) error {
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
func (p *PassthroughProxy) copyWithBufferAndContext(ctx context.Context, dst, src net.Conn) error {
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

		// If n == 0 and shouldContinue == false and err == nil,
		// it means the connection was closed gracefully
		if n == 0 {
			return nil
		}

		if err := p.writeWithDeadline(dst, buf[:n]); err != nil {
			return err
		}
	}
}

// readWithDeadline reads from the connection with a deadline for context checking.
// Returns bytes read, whether to continue the loop, and any error.
func (p *PassthroughProxy) readWithDeadline(src net.Conn, buf []byte) (bytesRead int, shouldContinue bool, err error) {
	if err := src.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return 0, false, handlePassthroughConnError(err)
	}

	n, err := src.Read(buf)
	if err != nil {
		cont, readErr := handlePassthroughReadError(err)
		return 0, cont, readErr
	}

	return n, false, nil
}

// writeWithDeadline writes data to the connection with a deadline.
func (p *PassthroughProxy) writeWithDeadline(dst net.Conn, data []byte) error {
	if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return handlePassthroughConnError(err)
	}

	_, err := dst.Write(data)
	if err != nil {
		return handlePassthroughConnError(err)
	}

	return nil
}

// handlePassthroughConnError processes connection errors, returning nil for closed connections.
func handlePassthroughConnError(err error) error {
	if isClosedConnError(err) {
		return nil
	}
	return err
}

// handlePassthroughReadError processes read errors, returning whether to continue and any error.
func handlePassthroughReadError(err error) (shouldContinue bool, returnErr error) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true, nil // timeout, continue loop
	}
	if isClosedConnError(err) {
		return false, nil // closed, exit gracefully
	}
	return false, err // propagate error
}

// ProxyWithIdleTimeout proxies with idle timeout support.
func (p *PassthroughProxy) ProxyWithIdleTimeout(
	ctx context.Context,
	clientConn net.Conn,
	clientHello []byte,
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

	// Connect to backend
	backendAddr := endpoint.FullAddress()
	dialer := &net.Dialer{
		Timeout: connectTimeout,
	}

	backendConn, err := dialer.DialContext(ctx, "tcp", backendAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to backend %s: %w", backendAddr, err)
	}
	defer backendConn.Close()

	p.logger.Debug("TLS passthrough connected to backend with idle timeout",
		zap.String("backend", backendRef.Name),
		zap.String("address", backendAddr),
		zap.String("client", clientConn.RemoteAddr().String()),
		zap.Duration("idleTimeout", idleTimeout),
	)

	// Forward the ClientHello to the backend
	if len(clientHello) > 0 {
		if _, err := backendConn.Write(clientHello); err != nil {
			return fmt.Errorf("failed to forward ClientHello: %w", err)
		}
	}

	// Proxy data bidirectionally with idle timeout
	return p.bidirectionalCopyWithTimeout(ctx, clientConn, backendConn, idleTimeout)
}

// bidirectionalCopyWithTimeout copies data bidirectionally with idle timeout.
// It properly handles context cancellation and ensures both copy goroutines exit.
func (p *PassthroughProxy) bidirectionalCopyWithTimeout(
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
		errCh <- p.copyWithTimeoutAndContext(copyCtx, conn2, conn1, idleTimeout)
	}()

	// Copy from conn2 to conn1
	go func() {
		errCh <- p.copyWithTimeoutAndContext(copyCtx, conn1, conn2, idleTimeout)
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

// copyWithTimeoutAndContext copies data with idle timeout support and context cancellation.
func (p *PassthroughProxy) copyWithTimeoutAndContext(
	ctx context.Context,
	dst, src net.Conn,
	idleTimeout time.Duration,
) error {
	bufPtr := p.bufferPool.Get().(*[]byte)
	defer p.bufferPool.Put(bufPtr)
	buf := *bufPtr

	checkInterval := calculatePassthroughCheckInterval(idleTimeout)

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

		// If n == 0 and shouldContinue == false and err == nil,
		// it means the connection was closed gracefully
		if n == 0 {
			return nil
		}

		if err := p.writeWithTimeoutDeadline(dst, buf[:n], idleTimeout); err != nil {
			return err
		}
	}
}

// calculatePassthroughCheckInterval returns the check interval for context cancellation.
// Uses a shorter interval to respond to context cancellation quickly.
func calculatePassthroughCheckInterval(idleTimeout time.Duration) time.Duration {
	if idleTimeout > 1*time.Second {
		return 1 * time.Second
	}
	return idleTimeout
}

// readWithTimeoutDeadline reads from the connection with a configurable deadline.
// Returns bytes read, whether to continue the loop, and any error.
func (p *PassthroughProxy) readWithTimeoutDeadline(
	src net.Conn,
	buf []byte,
	deadline time.Duration,
) (bytesRead int, shouldContinue bool, err error) {
	if err := src.SetReadDeadline(time.Now().Add(deadline)); err != nil {
		return 0, false, handlePassthroughConnError(err)
	}

	n, err := src.Read(buf)
	if err != nil {
		cont, readErr := handlePassthroughReadErrorWithEOF(err)
		return 0, cont, readErr
	}

	return n, false, nil
}

// writeWithTimeoutDeadline writes data to the connection with a configurable deadline.
func (p *PassthroughProxy) writeWithTimeoutDeadline(dst net.Conn, data []byte, timeout time.Duration) error {
	if err := dst.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return handlePassthroughConnError(err)
	}

	_, err := dst.Write(data)
	if err != nil {
		return handlePassthroughConnError(err)
	}

	return nil
}

// handlePassthroughReadErrorWithEOF processes read errors including EOF, returning whether to continue and any error.
func handlePassthroughReadErrorWithEOF(err error) (shouldContinue bool, returnErr error) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true, nil // timeout, continue loop
	}
	if err == io.EOF || errors.Is(err, io.ErrClosedPipe) {
		return false, nil // EOF or closed pipe, exit gracefully
	}
	if isClosedConnError(err) {
		return false, nil // closed, exit gracefully
	}
	return false, err // propagate error
}

// isClosedConnError checks if the error is due to a closed connection.
func isClosedConnError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	// Handle io.ErrClosedPipe which occurs with net.Pipe() connections
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	if netErr, ok := err.(*net.OpError); ok {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return false
}

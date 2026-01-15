// Package tls provides the TLS server implementation for the API Gateway.
package tls

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
func NewPassthroughProxyWithConfig(manager *backend.Manager, logger *zap.Logger, config *PassthroughProxyConfig) *PassthroughProxy {
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
				return make([]byte, bufferSize)
			},
		},
	}
}

// Proxy proxies a TLS connection to a backend without terminating TLS.
// The clientHello parameter contains the already-read ClientHello bytes that need to be
// forwarded to the backend.
func (p *PassthroughProxy) Proxy(ctx context.Context, clientConn net.Conn, clientHello []byte, backendRef *backend.Backend) error {
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
func (p *PassthroughProxy) ProxyWithAddress(ctx context.Context, clientConn net.Conn, clientHello []byte, backendAddr string, timeout time.Duration) error {
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
		conn1.Close()
		conn2.Close()
		firstErr = ctx.Err()
	case firstErr = <-errCh:
		// One direction completed, close both connections to signal the other
		conn1.Close()
		conn2.Close()
	}

	// Cancel the copy context to signal any remaining goroutines
	cancel()

	// Wait for the other direction to complete
	<-errCh

	return firstErr
}

// copyWithBuffer copies data from src to dst using a pooled buffer.
func (p *PassthroughProxy) copyWithBuffer(dst, src net.Conn) error {
	buf := p.bufferPool.Get().([]byte)
	defer p.bufferPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	if err != nil && !isClosedConnError(err) {
		return err
	}
	return nil
}

// copyWithBufferAndContext copies data from src to dst using a pooled buffer,
// respecting context cancellation.
func (p *PassthroughProxy) copyWithBufferAndContext(ctx context.Context, dst, src net.Conn) error {
	buf := p.bufferPool.Get().([]byte)
	defer p.bufferPool.Put(buf)

	for {
		// Check context before each read
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set a short read deadline to allow periodic context checks
		if err := src.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
			if isClosedConnError(err) {
				return nil
			}
			return err
		}

		n, err := src.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout, check context and continue
				continue
			}
			if isClosedConnError(err) {
				return nil
			}
			return err
		}

		if n > 0 {
			// Reset write deadline
			if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				if isClosedConnError(err) {
					return nil
				}
				return err
			}

			_, err = dst.Write(buf[:n])
			if err != nil {
				if isClosedConnError(err) {
					return nil
				}
				return err
			}
		}
	}
}

// ProxyWithIdleTimeout proxies with idle timeout support.
func (p *PassthroughProxy) ProxyWithIdleTimeout(ctx context.Context, clientConn net.Conn, clientHello []byte, backendRef *backend.Backend, connectTimeout, idleTimeout time.Duration) error {
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
func (p *PassthroughProxy) bidirectionalCopyWithTimeout(ctx context.Context, conn1, conn2 net.Conn, idleTimeout time.Duration) error {
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
		conn1.Close()
		conn2.Close()
		firstErr = ctx.Err()
	case firstErr = <-errCh:
		// One direction completed, close both connections to signal the other
		conn1.Close()
		conn2.Close()
	}

	// Cancel the copy context to signal any remaining goroutines
	cancel()

	// Wait for the other direction to complete
	<-errCh

	return firstErr
}

// copyWithTimeout copies data with idle timeout support.
func (p *PassthroughProxy) copyWithTimeout(dst, src net.Conn, idleTimeout time.Duration) error {
	return p.copyWithTimeoutAndContext(context.Background(), dst, src, idleTimeout)
}

// copyWithTimeoutAndContext copies data with idle timeout support and context cancellation.
func (p *PassthroughProxy) copyWithTimeoutAndContext(ctx context.Context, dst, src net.Conn, idleTimeout time.Duration) error {
	buf := p.bufferPool.Get().([]byte)
	defer p.bufferPool.Put(buf)

	// Use a shorter check interval to respond to context cancellation quickly
	checkInterval := idleTimeout
	if checkInterval > 1*time.Second {
		checkInterval = 1 * time.Second
	}

	for {
		// Check context before each read
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set read deadline - use the shorter of idle timeout or check interval
		// to allow periodic context checks
		if err := src.SetReadDeadline(time.Now().Add(checkInterval)); err != nil {
			if isClosedConnError(err) {
				return nil
			}
			return err
		}

		n, err := src.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if this is an idle timeout or just a check interval timeout
				// For simplicity, we'll just check context and continue
				continue
			}
			if err == io.EOF {
				return nil
			}
			if isClosedConnError(err) {
				return nil
			}
			return err
		}

		if n > 0 {
			// Reset write deadline
			if err := dst.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
				if isClosedConnError(err) {
					return nil
				}
				return err
			}

			_, err = dst.Write(buf[:n])
			if err != nil {
				if isClosedConnError(err) {
					return nil
				}
				return err
			}
		}
	}
}

// isClosedConnError checks if the error is due to a closed connection.
func isClosedConnError(err error) bool {
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

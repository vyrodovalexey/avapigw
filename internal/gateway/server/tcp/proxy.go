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
				return make([]byte, bufferSize)
			},
		},
	}
}

// Proxy proxies data between the client connection and a backend.
func (p *Proxy) Proxy(ctx context.Context, clientConn net.Conn, backendRef *backend.Backend, timeout time.Duration) error {
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
func (p *Proxy) ProxyWithAddress(ctx context.Context, clientConn net.Conn, backendAddr string, timeout time.Duration) error {
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

// copyWithBufferAndContext copies data from src to dst using a pooled buffer,
// respecting context cancellation.
func (p *Proxy) copyWithBufferAndContext(ctx context.Context, dst, src net.Conn) error {
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
			if isClosedError(err) {
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
			if isClosedError(err) {
				return nil
			}
			return err
		}

		if n > 0 {
			// Reset write deadline
			if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				if isClosedError(err) {
					return nil
				}
				return err
			}

			_, err = dst.Write(buf[:n])
			if err != nil {
				if isClosedError(err) {
					return nil
				}
				return err
			}
		}
	}
}

// copyWithBuffer copies data from src to dst using a pooled buffer.
func (p *Proxy) copyWithBuffer(dst, src net.Conn) error {
	buf := p.bufferPool.Get().([]byte)
	defer p.bufferPool.Put(buf)

	_, err := io.CopyBuffer(dst, src, buf)
	if err != nil && !isClosedError(err) {
		return err
	}
	return nil
}

// CopyWithTimeout copies data with idle timeout support.
func (p *Proxy) CopyWithTimeout(dst, src net.Conn, idleTimeout time.Duration) error {
	return p.CopyWithTimeoutAndContext(context.Background(), dst, src, idleTimeout)
}

// CopyWithTimeoutAndContext copies data with idle timeout support and context cancellation.
func (p *Proxy) CopyWithTimeoutAndContext(ctx context.Context, dst, src net.Conn, idleTimeout time.Duration) error {
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
			if isClosedError(err) {
				return nil
			}
			return err
		}

		n, err := src.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if this is an idle timeout or just a check interval timeout
				// For idle timeout, we need to track the last activity time
				// For simplicity, we'll just check context and continue
				continue
			}
			if err == io.EOF {
				return nil
			}
			if isClosedError(err) {
				return nil
			}
			return err
		}

		if n > 0 {
			// Reset write deadline
			if err := dst.SetWriteDeadline(time.Now().Add(idleTimeout)); err != nil {
				if isClosedError(err) {
					return nil
				}
				return err
			}

			_, err = dst.Write(buf[:n])
			if err != nil {
				if isClosedError(err) {
					return nil
				}
				return err
			}
		}
	}
}

// ProxyWithIdleTimeout proxies data with idle timeout support.
func (p *Proxy) ProxyWithIdleTimeout(ctx context.Context, clientConn net.Conn, backendRef *backend.Backend, connectTimeout, idleTimeout time.Duration) error {
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
func (p *Proxy) bidirectionalCopyWithTimeout(ctx context.Context, conn1, conn2 net.Conn, idleTimeout time.Duration) error {
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

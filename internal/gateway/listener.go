package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// Listener represents an HTTP listener.
type Listener struct {
	config  config.Listener
	server  *http.Server
	handler http.Handler
	logger  observability.Logger
	running atomic.Bool
}

// ListenerOption is a functional option for configuring a listener.
type ListenerOption func(*Listener)

// WithListenerLogger sets the logger for the listener.
func WithListenerLogger(logger observability.Logger) ListenerOption {
	return func(l *Listener) {
		l.logger = logger
	}
}

// NewListener creates a new listener.
func NewListener(
	cfg config.Listener,
	handler http.Handler,
	opts ...ListenerOption,
) (*Listener, error) {
	l := &Listener{
		config:  cfg,
		handler: handler,
		logger:  observability.NopLogger(),
	}

	for _, opt := range opts {
		opt(l)
	}

	return l, nil
}

// Name returns the listener name.
func (l *Listener) Name() string {
	return l.config.Name
}

// Port returns the listener port.
func (l *Listener) Port() int {
	return l.config.Port
}

// Address returns the listener address.
func (l *Listener) Address() string {
	bind := l.config.Bind
	if bind == "" {
		bind = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", bind, l.config.Port)
}

// Start starts the listener.
func (l *Listener) Start(ctx context.Context) error {
	if l.running.Load() {
		return fmt.Errorf("listener %s is already running", l.config.Name)
	}

	addr := l.Address()

	l.server = &http.Server{
		Addr:              addr,
		Handler:           l.handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	// Create listener with context
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	l.running.Store(true)

	l.logger.Info("listener started",
		observability.String("name", l.config.Name),
		observability.String("address", addr),
		observability.String("protocol", l.config.Protocol),
	)

	go l.serve(ln)

	return nil
}

// serve starts serving requests.
func (l *Listener) serve(ln net.Listener) {
	var err error
	if l.config.Protocol == "HTTPS" {
		// TODO: Add TLS support
		err = l.server.ServeTLS(ln, "", "")
	} else {
		err = l.server.Serve(ln)
	}

	if err != nil && err != http.ErrServerClosed {
		l.logger.Error("listener error",
			observability.String("name", l.config.Name),
			observability.Error(err),
		)
	}
	l.running.Store(false)
}

// Stop stops the listener gracefully.
func (l *Listener) Stop(ctx context.Context) error {
	if !l.running.Load() {
		return nil
	}

	l.logger.Info("stopping listener",
		observability.String("name", l.config.Name),
	)

	if err := l.server.Shutdown(ctx); err != nil {
		if closeErr := l.server.Close(); closeErr != nil {
			return fmt.Errorf("failed to close listener: %w", closeErr)
		}
		return fmt.Errorf("failed to shutdown listener gracefully: %w", err)
	}

	l.running.Store(false)

	l.logger.Info("listener stopped",
		observability.String("name", l.config.Name),
	)

	return nil
}

// IsRunning returns true if the listener is running.
func (l *Listener) IsRunning() bool {
	return l.running.Load()
}

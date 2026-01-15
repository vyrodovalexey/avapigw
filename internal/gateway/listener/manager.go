// Package listener provides listener management for the API Gateway.
// It handles creating, starting, and stopping listeners for different protocols.
package listener

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TLS mode constants
const (
	tlsModePassthrough = "Passthrough"
)

// Manager manages multiple listeners for the gateway.
type Manager struct {
	listeners map[string]*Listener
	mu        sync.RWMutex
	logger    *zap.Logger
	started   bool
}

// Listener represents a network listener with its configuration.
type Listener struct {
	Name     string
	Port     int
	Protocol string
	Hostname string
	TLS      *tls.Config
	Server   interface{} // *http.Server or *grpc.Server
	listener net.Listener
	handler  http.Handler
	running  bool
	mu       sync.RWMutex
}

// ListenerConfig holds configuration for creating a new listener.
type ListenerConfig struct {
	Name     string
	Port     int
	Protocol string
	Hostname string
	TLS      *TLSConfig
	Handler  http.Handler
}

// TLSConfig holds TLS configuration for a listener.
type TLSConfig struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	MinVersion uint16
	MaxVersion uint16
}

// NewManager creates a new listener manager.
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		listeners: make(map[string]*Listener),
		logger:    logger,
	}
}

// AddListener adds a new listener with the given configuration.
func (m *Manager) AddListener(config ListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[config.Name]; exists {
		return fmt.Errorf("listener %s already exists", config.Name)
	}

	listener := &Listener{
		Name:     config.Name,
		Port:     config.Port,
		Protocol: config.Protocol,
		Hostname: config.Hostname,
		handler:  config.Handler,
	}

	// Configure TLS if provided
	if config.TLS != nil {
		tlsConfig, err := LoadTLSConfig(config.TLS)
		if err != nil {
			return fmt.Errorf("failed to load TLS config for listener %s: %w", config.Name, err)
		}
		listener.TLS = tlsConfig
	}

	m.listeners[config.Name] = listener
	m.logger.Info("listener added",
		zap.String("name", config.Name),
		zap.Int("port", config.Port),
		zap.String("protocol", config.Protocol),
	)

	// If manager is already started, start this listener too
	if m.started {
		if err := m.startListener(listener); err != nil {
			delete(m.listeners, config.Name)
			return fmt.Errorf("failed to start listener %s: %w", config.Name, err)
		}
	}

	return nil
}

// RemoveListener removes a listener by name.
func (m *Manager) RemoveListener(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, exists := m.listeners[name]
	if !exists {
		return fmt.Errorf("listener %s not found", name)
	}

	// Stop the listener if running
	if err := m.stopListener(listener); err != nil {
		m.logger.Warn("error stopping listener",
			zap.String("name", name),
			zap.Error(err),
		)
	}

	delete(m.listeners, name)
	m.logger.Info("listener removed", zap.String("name", name))

	return nil
}

// GetListener returns a listener by name.
func (m *Manager) GetListener(name string) *Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.listeners[name]
}

// ListListeners returns all listener names.
func (m *Manager) ListListeners() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	names := make([]string, 0, len(m.listeners))
	for name := range m.listeners {
		names = append(names, name)
	}
	return names
}

// Start starts all listeners.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return fmt.Errorf("manager already started")
	}

	m.logger.Info("starting listener manager", zap.Int("count", len(m.listeners)))

	for _, listener := range m.listeners {
		if err := m.startListener(listener); err != nil {
			// Stop already started listeners on error
			m.stopAllListeners()
			return fmt.Errorf("failed to start listener %s: %w", listener.Name, err)
		}
	}

	m.started = true
	m.logger.Info("listener manager started")

	return nil
}

// Stop stops all listeners gracefully.
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		return nil
	}

	m.logger.Info("stopping listener manager")

	var lastErr error
	for _, listener := range m.listeners {
		if err := m.stopListenerWithContext(ctx, listener); err != nil {
			m.logger.Error("error stopping listener",
				zap.String("name", listener.Name),
				zap.Error(err),
			)
			lastErr = err
		}
	}

	m.started = false
	m.logger.Info("listener manager stopped")

	return lastErr
}

// UpdateListener updates an existing listener's configuration.
func (m *Manager) UpdateListener(config ListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	listener, exists := m.listeners[config.Name]
	if !exists {
		return fmt.Errorf("listener %s not found", config.Name)
	}

	// If the listener is running, we need to restart it
	wasRunning := listener.running
	if wasRunning {
		if err := m.stopListener(listener); err != nil {
			return fmt.Errorf("failed to stop listener for update: %w", err)
		}
	}

	// Update configuration
	listener.Port = config.Port
	listener.Protocol = config.Protocol
	listener.Hostname = config.Hostname
	listener.handler = config.Handler

	// Update TLS if provided
	if config.TLS != nil {
		tlsConfig, err := LoadTLSConfig(config.TLS)
		if err != nil {
			return fmt.Errorf("failed to load TLS config: %w", err)
		}
		listener.TLS = tlsConfig
	} else {
		listener.TLS = nil
	}

	// Restart if it was running
	if wasRunning {
		if err := m.startListener(listener); err != nil {
			return fmt.Errorf("failed to restart listener after update: %w", err)
		}
	}

	m.logger.Info("listener updated", zap.String("name", config.Name))

	return nil
}

// startListener starts a single listener.
func (m *Manager) startListener(l *Listener) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	addr := fmt.Sprintf(":%d", l.Port)

	var err error
	if l.TLS != nil {
		l.listener, err = tls.Listen("tcp", addr, l.TLS)
	} else {
		lc := &net.ListenConfig{}
		l.listener, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to create listener on %s: %w", addr, err)
	}

	// Create HTTP server with ReadHeaderTimeout to prevent Slowloris attacks
	server := &http.Server{
		Handler:           l.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	l.Server = server

	// Start serving in a goroutine
	go func() {
		m.logger.Info("listener started",
			zap.String("name", l.Name),
			zap.Int("port", l.Port),
			zap.String("protocol", l.Protocol),
		)

		if err := server.Serve(l.listener); err != nil && err != http.ErrServerClosed {
			m.logger.Error("listener error",
				zap.String("name", l.Name),
				zap.Error(err),
			)
		}
	}()

	l.running = true
	return nil
}

// stopListener stops a single listener.
func (m *Manager) stopListener(l *Listener) error {
	return m.stopListenerWithContext(context.Background(), l)
}

// stopListenerWithContext stops a single listener with context for graceful shutdown.
func (m *Manager) stopListenerWithContext(ctx context.Context, l *Listener) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	if server, ok := l.Server.(*http.Server); ok {
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown server: %w", err)
		}
	}

	l.running = false
	m.logger.Info("listener stopped", zap.String("name", l.Name))

	return nil
}

// stopAllListeners stops all listeners without locking (caller must hold lock).
func (m *Manager) stopAllListeners() {
	for _, listener := range m.listeners {
		if err := m.stopListener(listener); err != nil {
			m.logger.Warn("error stopping listener during cleanup",
				zap.String("name", listener.Name),
				zap.Error(err),
			)
		}
	}
}

// IsRunning returns whether the listener is currently running.
func (l *Listener) IsRunning() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.running
}

// GetAddress returns the listener's address.
func (l *Listener) GetAddress() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return fmt.Sprintf(":%d", l.Port)
}

// TCPListenerConfig holds configuration for a TCP listener.
type TCPListenerConfig struct {
	Name           string
	Port           int
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxConnections int
	TLS            *TLSConfig
}

// TLSListenerConfig holds configuration for a TLS listener.
type TLSListenerConfig struct {
	Name           string
	Port           int
	Mode           string // "Terminate" or "Passthrough"
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxConnections int
	TLS            *TLSConfig
}

// AddTCPListener adds a new TCP listener with the given configuration.
func (m *Manager) AddTCPListener(config TCPListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[config.Name]; exists {
		return fmt.Errorf("listener %s already exists", config.Name)
	}

	listener := &Listener{
		Name:     config.Name,
		Port:     config.Port,
		Protocol: "TCP",
	}

	// Configure TLS if provided
	if config.TLS != nil {
		tlsConfig, err := LoadTLSConfig(config.TLS)
		if err != nil {
			return fmt.Errorf("failed to load TLS config for TCP listener %s: %w", config.Name, err)
		}
		listener.TLS = tlsConfig
	}

	m.listeners[config.Name] = listener
	m.logger.Info("TCP listener added",
		zap.String("name", config.Name),
		zap.Int("port", config.Port),
		zap.Int("maxConnections", config.MaxConnections),
	)

	// If manager is already started, start this listener too
	if m.started {
		if err := m.startTCPListener(listener); err != nil {
			delete(m.listeners, config.Name)
			return fmt.Errorf("failed to start TCP listener %s: %w", config.Name, err)
		}
	}

	return nil
}

// AddTLSListener adds a new TLS listener with the given configuration.
func (m *Manager) AddTLSListener(config TLSListenerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.listeners[config.Name]; exists {
		return fmt.Errorf("listener %s already exists", config.Name)
	}

	protocol := "TLS"
	if config.Mode == tlsModePassthrough {
		protocol = "TLS-Passthrough"
	}

	listener := &Listener{
		Name:     config.Name,
		Port:     config.Port,
		Protocol: protocol,
	}

	// Configure TLS if provided and mode is Terminate
	if config.TLS != nil && config.Mode != tlsModePassthrough {
		tlsConfig, err := LoadTLSConfig(config.TLS)
		if err != nil {
			return fmt.Errorf("failed to load TLS config for TLS listener %s: %w", config.Name, err)
		}
		listener.TLS = tlsConfig
	}

	m.listeners[config.Name] = listener
	m.logger.Info("TLS listener added",
		zap.String("name", config.Name),
		zap.Int("port", config.Port),
		zap.String("mode", config.Mode),
		zap.Int("maxConnections", config.MaxConnections),
	)

	// If manager is already started, start this listener too
	if m.started {
		if err := m.startTLSListener(listener, config.Mode); err != nil {
			delete(m.listeners, config.Name)
			return fmt.Errorf("failed to start TLS listener %s: %w", config.Name, err)
		}
	}

	return nil
}

// startTCPListener starts a TCP listener.
func (m *Manager) startTCPListener(l *Listener) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	addr := fmt.Sprintf(":%d", l.Port)

	var err error
	if l.TLS != nil {
		l.listener, err = tls.Listen("tcp", addr, l.TLS)
	} else {
		lc := &net.ListenConfig{}
		l.listener, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to create TCP listener on %s: %w", addr, err)
	}

	l.running = true
	m.logger.Info("TCP listener started",
		zap.String("name", l.Name),
		zap.Int("port", l.Port),
	)

	return nil
}

// startTLSListener starts a TLS listener.
func (m *Manager) startTLSListener(l *Listener, mode string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	addr := fmt.Sprintf(":%d", l.Port)
	lc := &net.ListenConfig{}

	var err error
	switch {
	case mode == tlsModePassthrough:
		// For passthrough, use raw TCP listener
		l.listener, err = lc.Listen(context.Background(), "tcp", addr)
	case l.TLS != nil:
		// For termination, use TLS listener
		l.listener, err = tls.Listen("tcp", addr, l.TLS)
	default:
		l.listener, err = lc.Listen(context.Background(), "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to create TLS listener on %s: %w", addr, err)
	}

	l.running = true
	m.logger.Info("TLS listener started",
		zap.String("name", l.Name),
		zap.Int("port", l.Port),
		zap.String("mode", mode),
	)

	return nil
}

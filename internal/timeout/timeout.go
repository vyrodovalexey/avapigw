// Package timeout provides timeout management for the API Gateway.
package timeout

import (
	"context"
	"time"
)

// Timeout holds timeout configuration for different phases of request processing.
type Timeout struct {
	// Request is the total timeout for the entire request.
	request time.Duration

	// Backend is the timeout for backend requests.
	backend time.Duration

	// Idle is the timeout for idle connections.
	idle time.Duration

	// Connect is the timeout for establishing connections.
	connect time.Duration

	// Read is the timeout for reading response.
	read time.Duration

	// Write is the timeout for writing request.
	write time.Duration
}

// NewTimeout creates a new Timeout with the specified durations.
func NewTimeout(request, backend, idle time.Duration) *Timeout {
	return &Timeout{
		request: request,
		backend: backend,
		idle:    idle,
	}
}

// NewTimeoutWithDefaults creates a new Timeout with default values.
func NewTimeoutWithDefaults() *Timeout {
	return &Timeout{
		request: 30 * time.Second,
		backend: 30 * time.Second,
		idle:    120 * time.Second,
		connect: 10 * time.Second,
		read:    30 * time.Second,
		write:   30 * time.Second,
	}
}

// RequestContext returns a context with the request timeout.
func (t *Timeout) RequestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if t.request <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, t.request)
}

// BackendContext returns a context with the backend timeout.
func (t *Timeout) BackendContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if t.backend <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, t.backend)
}

// ConnectContext returns a context with the connect timeout.
func (t *Timeout) ConnectContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if t.connect <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, t.connect)
}

// Request returns the request timeout duration.
func (t *Timeout) Request() time.Duration {
	return t.request
}

// Backend returns the backend timeout duration.
func (t *Timeout) Backend() time.Duration {
	return t.backend
}

// Idle returns the idle timeout duration.
func (t *Timeout) Idle() time.Duration {
	return t.idle
}

// Connect returns the connect timeout duration.
func (t *Timeout) Connect() time.Duration {
	return t.connect
}

// Read returns the read timeout duration.
func (t *Timeout) Read() time.Duration {
	return t.read
}

// Write returns the write timeout duration.
func (t *Timeout) Write() time.Duration {
	return t.write
}

// WithRequest sets the request timeout.
func (t *Timeout) WithRequest(d time.Duration) *Timeout {
	t.request = d
	return t
}

// WithBackend sets the backend timeout.
func (t *Timeout) WithBackend(d time.Duration) *Timeout {
	t.backend = d
	return t
}

// WithIdle sets the idle timeout.
func (t *Timeout) WithIdle(d time.Duration) *Timeout {
	t.idle = d
	return t
}

// WithConnect sets the connect timeout.
func (t *Timeout) WithConnect(d time.Duration) *Timeout {
	t.connect = d
	return t
}

// WithRead sets the read timeout.
func (t *Timeout) WithRead(d time.Duration) *Timeout {
	t.read = d
	return t
}

// WithWrite sets the write timeout.
func (t *Timeout) WithWrite(d time.Duration) *Timeout {
	t.write = d
	return t
}

// Config holds timeout configuration.
type Config struct {
	Request time.Duration
	Backend time.Duration
	Idle    time.Duration
	Connect time.Duration
	Read    time.Duration
	Write   time.Duration
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Request: 30 * time.Second,
		Backend: 30 * time.Second,
		Idle:    120 * time.Second,
		Connect: 10 * time.Second,
		Read:    30 * time.Second,
		Write:   30 * time.Second,
	}
}

// NewTimeoutFromConfig creates a Timeout from a Config.
func NewTimeoutFromConfig(cfg *Config) *Timeout {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Timeout{
		request: cfg.Request,
		backend: cfg.Backend,
		idle:    cfg.Idle,
		connect: cfg.Connect,
		read:    cfg.Read,
		write:   cfg.Write,
	}
}

// Validate validates and normalizes the timeout configuration.
func (c *Config) Validate() {
	if c.Request <= 0 {
		c.Request = 30 * time.Second
	}
	if c.Backend <= 0 {
		c.Backend = 30 * time.Second
	}
	if c.Idle <= 0 {
		c.Idle = 120 * time.Second
	}
	if c.Connect <= 0 {
		c.Connect = 10 * time.Second
	}
	if c.Read <= 0 {
		c.Read = 30 * time.Second
	}
	if c.Write <= 0 {
		c.Write = 30 * time.Second
	}
}

// TimeoutError represents a timeout error.
type TimeoutError struct {
	Phase   string
	Timeout time.Duration
}

func (e *TimeoutError) Error() string {
	return e.Phase + " timeout after " + e.Timeout.String()
}

// IsTimeout returns true if the error is a timeout error.
func IsTimeout(err error) bool {
	_, ok := err.(*TimeoutError)
	return ok
}

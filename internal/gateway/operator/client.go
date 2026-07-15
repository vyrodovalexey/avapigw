// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// clientStopTimeout is the timeout for waiting for operator client goroutines to stop.
const clientStopTimeout = 5 * time.Second

// Client errors.
var (
	ErrNotConnected       = errors.New("client is not connected to operator")
	ErrAlreadyStarted     = errors.New("client is already started")
	ErrNotStarted         = errors.New("client is not started")
	ErrRegistrationFailed = errors.New("gateway registration failed")
	ErrStreamClosed       = errors.New("configuration stream closed")
	ErrInvalidConfig      = errors.New("invalid configuration")
)

// ConfigUpdateHandler is a callback function for handling configuration updates.
type ConfigUpdateHandler func(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error

// SnapshotHandler is a callback function for handling configuration snapshots.
type SnapshotHandler func(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error

// ReconnectListener is invoked after every successful gateway registration
// with the operator — the initial connect and every stream re-establishment.
// It runs BEFORE the registration's initial snapshot is applied so listeners
// (e.g. the ConfigHandler's snapshot regression window) can arm themselves
// against the snapshots that follow the (re)connect.
type ReconnectListener func()

// Client is the operator client that connects to the avapigw operator.
type Client struct {
	config *Config
	conn   *grpc.ClientConn
	client operatorv1alpha1.ConfigurationServiceClient
	logger observability.Logger
	tracer trace.Tracer

	metrics *clientMetrics

	sessionID           string
	lastAppliedVersion  string
	lastAppliedSequence int64
	heartbeatInterval   time.Duration
	startTime           time.Time
	lastConfigAppliedAt time.Time
	mu                  sync.RWMutex
	connected           atomic.Bool
	started             atomic.Bool

	// stopCh/stoppedCh/wg belong to the CURRENT background-goroutine
	// generation and are replaced by Start under mu. Long-lived goroutines
	// never re-read these fields: they receive their own generation's stop
	// channel as an argument (generation capture pattern), so a goroutine
	// stranded by a timed-out Stop still exits on ITS OWN closed channel
	// instead of blocking on a newer, open one. The WaitGroup is
	// per-generation as well, so a new Start never calls Add concurrently
	// with a stale Stop waiter's Wait.
	stopCh    chan struct{}
	stoppedCh chan struct{}
	wg        *sync.WaitGroup

	// reconnectAttempts is atomic because a goroutine stranded past a
	// timed-out Stop may still be draining its reconnect loop while the new
	// generation's stream loop also reconnects.
	reconnectAttempts atomic.Int64

	// bgCancel cancels the long-lived background context that governs the
	// background streaming and heartbeat goroutines. That context is
	// intentionally decoupled from the (potentially short-lived) context
	// passed to Start so that a bounded initial connect/register retry
	// deadline cannot cancel the steady-state loops once Start succeeds.
	// Like the fields above it is per-generation, replaced by Start under mu
	// and invoked by Stop.
	bgCancel context.CancelFunc

	// stopTimeout bounds Stop's wait for background goroutines to drain. Zero
	// means clientStopTimeout; overridable in tests (mirrors the
	// backend/health stopTimeout seam). Set before Start; never mutated
	// afterwards.
	stopTimeout time.Duration

	// Callbacks
	onConfigUpdate ConfigUpdateHandler
	onSnapshot     SnapshotHandler
	onReconnect    ReconnectListener

	// Status provider for heartbeats
	statusProvider StatusProvider
}

// StatusProvider provides gateway status information for heartbeats.
type StatusProvider interface {
	GetActiveConnections() int64
	GetRequestsPerSecond() float64
	GetErrorRate() float64
	GetMemoryBytes() int64
	GetCPUUsage() float64
	IsHealthy() bool
}

// Option is a functional option for configuring the client.
type Option func(*Client)

// WithLogger sets the logger for the client.
func WithLogger(logger observability.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithMetricsRegistry sets the Prometheus registry for metrics.
func WithMetricsRegistry(registry prometheus.Registerer) Option {
	return func(c *Client) {
		c.metrics = newClientMetrics(registry)
	}
}

// WithConfigUpdateHandler sets the callback for configuration updates.
func WithConfigUpdateHandler(handler ConfigUpdateHandler) Option {
	return func(c *Client) {
		c.onConfigUpdate = handler
	}
}

// WithSnapshotHandler sets the callback for configuration snapshots.
func WithSnapshotHandler(handler SnapshotHandler) Option {
	return func(c *Client) {
		c.onSnapshot = handler
	}
}

// WithReconnectListener sets the listener invoked after every successful
// gateway registration (initial connect and reconnects).
func WithReconnectListener(listener ReconnectListener) Option {
	return func(c *Client) {
		c.onReconnect = listener
	}
}

// WithStatusProvider sets the status provider for heartbeats.
func WithStatusProvider(provider StatusProvider) Option {
	return func(c *Client) {
		c.statusProvider = provider
	}
}

// WithTracer sets the tracer for the client.
func WithTracer(tracer trace.Tracer) Option {
	return func(c *Client) {
		c.tracer = tracer
	}
}

// NewClient creates a new operator client.
func NewClient(config *Config, opts ...Option) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: config is nil", ErrInvalidConfig)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	c := &Client{
		config:            config,
		logger:            observability.NopLogger(),
		tracer:            otel.Tracer("operator-client"),
		heartbeatInterval: config.GetHeartbeatInterval(),
		stopCh:            make(chan struct{}),
		stoppedCh:         make(chan struct{}),
		wg:                &sync.WaitGroup{},
	}

	for _, opt := range opts {
		opt(c)
	}

	// Initialize metrics if not set
	if c.metrics == nil {
		c.metrics = newClientMetrics(nil)
	}

	return c, nil
}

// Connect establishes connection to the operator.
func (c *Client) Connect(ctx context.Context) error {
	_, span := c.tracer.Start(ctx, "operator.Connect",
		trace.WithAttributes(
			attribute.String("operator.address", c.config.Address),
			attribute.Bool("operator.tls_enabled", c.config.IsTLSEnabled()),
		),
	)
	defer span.End()

	c.logger.Info("connecting to operator",
		observability.String("address", c.config.Address),
		observability.Bool("tls_enabled", c.config.IsTLSEnabled()),
	)

	// Build dial options
	dialOpts, err := c.buildDialOptions()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to build dial options: %w", err)
	}

	// Create connection
	// Note: grpc.NewClient doesn't use context for dialing, connection is lazy
	conn, err := grpc.NewClient(c.config.Address, dialOpts...)
	if err != nil {
		span.RecordError(err)
		c.logger.Error("failed to connect to operator",
			observability.String("address", c.config.Address),
			observability.Error(err),
		)
		return fmt.Errorf("failed to connect to operator: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.client = operatorv1alpha1.NewConfigurationServiceClient(conn)
	c.mu.Unlock()

	c.logger.Info("connected to operator",
		observability.String("address", c.config.Address),
	)

	return nil
}

// buildDialOptions builds gRPC dial options.
func (c *Client) buildDialOptions() ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	// Configure TLS or insecure
	if c.config.IsTLSEnabled() {
		tlsConfig, err := c.buildTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	return opts, nil
}

// buildTLSConfig builds TLS configuration.
func (c *Client) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := c.config.TLS
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load client certificate if provided
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if tlsCfg.CAFile != "" {
		caCert, err := os.ReadFile(tlsCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
	}

	// Set server name if provided
	if tlsCfg.ServerName != "" {
		config.ServerName = tlsCfg.ServerName
	}

	// Set insecure skip verify (dev only)
	config.InsecureSkipVerify = tlsCfg.InsecureSkipVerify //nolint:gosec // Configurable for dev environments

	return config, nil
}

// Start starts the client (registration, streaming, heartbeat).
//
// The stream/heartbeat loops run under a fresh context.Background()-rooted
// context rather than inheriting the caller's (potentially short-lived) ctx.
// Inheriting it would cancel the steady-state loops the moment the caller's
// initial-connect retry deadline fires. See the comment on c.bgCancel.
//
// Start and Stop are lifecycle methods intended to be invoked sequentially
// by a single owner; they must not be called concurrently with each other.
//
//nolint:contextcheck // Start intentionally launches its long-lived background
func (c *Client) Start(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return ErrAlreadyStarted
	}

	ctx, span := c.tracer.Start(ctx, "operator.Start")
	defer span.End()

	// The initial connect + register RPCs run under the caller-provided ctx,
	// which may carry a bounded startup-retry deadline. That is correct: the
	// bring-up handshake should honor that deadline.
	//
	// The long-lived streaming/heartbeat loops, however, must NOT be tied to
	// that short-lived ctx — otherwise the caller's retry deadline (or its
	// defer cancel()) would immediately cancel the loops right after Start
	// returns, tearing down the freshly established stream. We therefore run
	// them under a dedicated background context that lives until Stop() is
	// called (via bgCancel). It is deliberately rooted at context.Background()
	// so it is independent of the initial-retry cancellation.
	bgCtx, bgCancel := context.WithCancel(context.Background())

	// Create fresh lifecycle primitives for this generation and publish them
	// under mu. The goroutines below capture the locals (generation capture
	// pattern) and never re-read the struct fields, so a goroutine left
	// behind by a previous timed-out Stop keeps observing its own (already
	// closed) stop channel and exits, instead of being stranded on the new,
	// open one.
	stopCh := make(chan struct{})
	stoppedCh := make(chan struct{})
	wg := &sync.WaitGroup{}
	c.mu.Lock()
	c.startTime = time.Now()
	c.stopCh = stopCh
	c.stoppedCh = stoppedCh
	c.wg = wg
	c.bgCancel = bgCancel
	c.mu.Unlock()

	// Connect if not already connected
	c.mu.RLock()
	hasConn := c.conn != nil
	c.mu.RUnlock()
	if !hasConn {
		if err := c.Connect(ctx); err != nil {
			bgCancel()
			c.started.Store(false)
			span.RecordError(err)
			return err
		}
	}

	// Register with operator
	if err := c.register(ctx); err != nil {
		bgCancel()
		c.started.Store(false)
		span.RecordError(err)
		return err
	}

	// Start background goroutines with WaitGroup coordination. They run under
	// the long-lived bgCtx so they survive after Start returns and are only
	// canceled by Stop().
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.runStreamLoop(bgCtx, stopCh)
	}()
	go func() {
		defer wg.Done()
		c.runHeartbeatLoop(bgCtx, stopCh)
	}()

	c.logger.Info("operator client started",
		observability.String("session_id", c.sessionID),
		observability.String("gateway_name", c.config.GatewayName),
		observability.String("gateway_namespace", c.config.GatewayNamespace),
	)

	return nil
}

// stopWaitTimeout returns the bounded wait for background-goroutine shutdown,
// falling back to clientStopTimeout when the seam was left unset (zero value).
func (c *Client) stopWaitTimeout() time.Duration {
	if c.stopTimeout > 0 {
		return c.stopTimeout
	}
	return clientStopTimeout
}

// Stop gracefully stops the client.
func (c *Client) Stop() error {
	if !c.started.CompareAndSwap(true, false) {
		return ErrNotStarted
	}

	c.logger.Info("stopping operator client")

	// Capture the current generation's lifecycle primitives under mu so this
	// Stop signals and waits on the same generation it observed, even if a
	// concurrent Start later replaces the struct fields.
	c.mu.RLock()
	stopCh := c.stopCh
	stoppedCh := c.stoppedCh
	wg := c.wg
	bgCancel := c.bgCancel
	c.mu.RUnlock()

	// Signal stop: close stopCh for select-based loop exits and cancel the
	// long-lived background context so any in-flight streaming/heartbeat RPCs
	// (which are bound to bgCtx, not stopCh) unblock promptly.
	close(stopCh)
	if bgCancel != nil {
		bgCancel()
	}

	// Wait for this generation's goroutines to finish with timeout. The
	// WaitGroup is per-generation, so a stale waiter from a timed-out Stop
	// can never race a newer Start's Add against its Wait.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines stopped cleanly
		c.logger.Debug("all operator client goroutines stopped")
	case <-time.After(c.stopWaitTimeout()):
		c.logger.Warn("timeout waiting for operator client goroutines to stop")
	}

	// Signal stoppedCh for any external waiters
	select {
	case <-stoppedCh:
		// Already closed
	default:
		close(stoppedCh)
	}

	// Close connection
	c.mu.Lock()
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			c.logger.Error("failed to close connection", observability.Error(err))
		}
		c.conn = nil
		c.client = nil
	}
	c.mu.Unlock()

	c.connected.Store(false)
	c.metrics.setConnected(false)

	c.logger.Info("operator client stopped")

	return nil
}

// IsConnected returns connection status.
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// SessionID returns the current session ID.
func (c *Client) SessionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionID
}

// SetConfigUpdateHandler sets the callback for config updates.
func (c *Client) SetConfigUpdateHandler(handler ConfigUpdateHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onConfigUpdate = handler
}

// SetSnapshotHandler sets the callback for snapshots.
func (c *Client) SetSnapshotHandler(handler SnapshotHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onSnapshot = handler
}

// serviceClient returns the current gRPC service client under the read lock.
// Background goroutines must use this accessor instead of reading c.client
// directly: Stop() nils the field under mu while a goroutine stranded past a
// timed-out Stop may still be draining, and a subsequent Start/Connect may
// concurrently replace it. Callers must handle a nil result (no active
// connection).
func (c *Client) serviceClient() operatorv1alpha1.ConfigurationServiceClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

// register registers the gateway with the operator.
func (c *Client) register(ctx context.Context) error {
	// Apply timeout for registration RPC call
	timeout := c.config.GetConnectionTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ctx, span := c.tracer.Start(ctx, "operator.Register")
	defer span.End()

	c.logger.Info("registering gateway with operator",
		observability.String("gateway_name", c.config.GatewayName),
		observability.String("gateway_namespace", c.config.GatewayNamespace),
		observability.Duration("timeout", timeout),
	)

	req := &operatorv1alpha1.RegisterGatewayRequest{
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:        c.config.GatewayName,
			Namespace:   c.config.GatewayNamespace,
			Version:     c.config.GatewayVersion,
			PodName:     c.config.GetPodName(),
			NodeName:    c.config.GetNodeName(),
			Labels:      c.config.Labels,
			Annotations: c.config.Annotations,
		},
		Capabilities: &operatorv1alpha1.GatewayCapabilities{
			HttpRoutes:     true,
			GrpcRoutes:     true,
			Websocket:      true,
			TlsTermination: true,
			Mtls:           true,
			RateLimiting:   true,
			CircuitBreaker: true,
			Caching:        true,
		},
	}

	cli := c.serviceClient()
	if cli == nil {
		c.metrics.incRegistrationErrors()
		span.RecordError(ErrNotConnected)
		return fmt.Errorf("%w: %w", ErrRegistrationFailed, ErrNotConnected)
	}

	resp, err := cli.RegisterGateway(ctx, req)
	if err != nil {
		c.metrics.incRegistrationErrors()
		span.RecordError(err)
		c.logger.Error("failed to register gateway",
			observability.Error(err),
		)
		return fmt.Errorf("%w: %w", ErrRegistrationFailed, err)
	}

	if !resp.Success {
		c.metrics.incRegistrationErrors()
		err := fmt.Errorf("%w: %s", ErrRegistrationFailed, resp.ErrorMessage)
		span.RecordError(err)
		c.logger.Error("gateway registration rejected",
			observability.String("error", resp.ErrorMessage),
		)
		return err
	}

	c.mu.Lock()
	c.sessionID = resp.SessionId
	if resp.HeartbeatInterval != nil {
		c.heartbeatInterval = resp.HeartbeatInterval.AsDuration()
	}
	heartbeatInterval := c.heartbeatInterval
	c.mu.Unlock()

	c.connected.Store(true)
	c.metrics.setConnected(true)

	span.SetAttributes(attribute.String("session_id", resp.SessionId))

	c.logger.Info("gateway registered successfully",
		observability.String("session_id", resp.SessionId),
		observability.Duration("heartbeat_interval", heartbeatInterval),
	)

	// Signal the (re)connect BEFORE applying the registration's initial
	// snapshot so listeners can arm the post-reconnect snapshot regression
	// window covering it. Read under the lock: register runs from both the
	// Start path and reconnect goroutines.
	c.mu.RLock()
	onReconnect := c.onReconnect
	c.mu.RUnlock()
	if onReconnect != nil {
		onReconnect()
	}

	// Apply initial configuration if provided
	if resp.InitialConfig != nil {
		if err := c.handleSnapshot(ctx, resp.InitialConfig); err != nil {
			c.logger.Error("failed to apply initial configuration",
				observability.Error(err),
			)
			// Don't fail registration, just log the error
		}
	}

	return nil
}

// runStreamLoop runs the configuration streaming loop with reconnection.
//
// stopCh is the goroutine's own generation stop channel, captured at spawn
// time (generation capture pattern). It must never be re-read from the
// struct: Start may replace c.stopCh for a newer generation while this
// goroutine is still draining after a timed-out Stop.
func (c *Client) runStreamLoop(ctx context.Context, stopCh <-chan struct{}) {
	// Note: WaitGroup.Done() is called by the parent goroutine wrapper in Start()
	// stoppedCh is now managed by Stop() method for proper coordination

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		if err := c.streamConfiguration(ctx, stopCh); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}

			c.logger.Error("configuration stream error",
				observability.Error(err),
			)
			c.metrics.incStreamErrors()
			c.connected.Store(false)
			c.metrics.setConnected(false)

			// Reconnect with backoff
			if !c.reconnectWithBackoff(ctx, stopCh) {
				return
			}
		}
	}
}

// streamConfiguration establishes and handles the configuration stream.
// stopCh is the calling goroutine's generation stop channel (see runStreamLoop).
func (c *Client) streamConfiguration(ctx context.Context, stopCh <-chan struct{}) error {
	ctx, span := c.tracer.Start(ctx, "operator.StreamConfiguration")
	defer span.End()

	c.mu.RLock()
	sessionID := c.sessionID
	lastVersion := c.lastAppliedVersion
	c.mu.RUnlock()

	req := &operatorv1alpha1.StreamConfigurationRequest{
		SessionId: sessionID,
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:        c.config.GatewayName,
			Namespace:   c.config.GatewayNamespace,
			Version:     c.config.GatewayVersion,
			PodName:     c.config.GetPodName(),
			NodeName:    c.config.GetNodeName(),
			Labels:      c.config.Labels,
			Annotations: c.config.Annotations,
		},
		LastConfigVersion: lastVersion,
		Namespaces:        c.config.Namespaces,
	}

	cli := c.serviceClient()
	if cli == nil {
		span.RecordError(ErrNotConnected)
		return fmt.Errorf("failed to start configuration stream: %w", ErrNotConnected)
	}

	stream, err := cli.StreamConfiguration(ctx, req)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to start configuration stream: %w", err)
	}

	c.logger.Info("configuration stream established",
		observability.String("session_id", sessionID),
	)

	for {
		select {
		case <-stopCh:
			return nil
		default:
		}

		update, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ErrStreamClosed
			}
			if status.Code(err) == codes.Canceled {
				return context.Canceled
			}
			span.RecordError(err)
			return fmt.Errorf("stream receive error: %w", err)
		}

		if err := c.handleUpdate(ctx, update); err != nil {
			c.logger.Error("failed to handle configuration update",
				observability.Error(err),
				observability.String("version", update.Version),
				observability.Int64("sequence", update.Sequence),
			)
			// Continue processing other updates
		}
	}
}

// handleUpdate processes a configuration update.
func (c *Client) handleUpdate(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
	ctx, span := c.tracer.Start(ctx, "operator.HandleUpdate",
		trace.WithAttributes(
			attribute.String("update.type", update.Type.String()),
			attribute.String("update.version", update.Version),
			attribute.Int64("update.sequence", update.Sequence),
		),
	)
	defer span.End()

	startTime := time.Now()
	updateType := update.Type.String()

	c.logger.Debug("received configuration update",
		observability.String("type", updateType),
		observability.String("version", update.Version),
		observability.Int64("sequence", update.Sequence),
	)

	// Check sequence ordering
	c.mu.RLock()
	lastSequence := c.lastAppliedSequence
	c.mu.RUnlock()

	if update.Sequence <= lastSequence && update.Type != operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC {
		c.logger.Warn("received out-of-order update, skipping",
			observability.Int64("received_sequence", update.Sequence),
			observability.Int64("last_sequence", lastSequence),
		)
		return nil
	}

	var err error
	switch update.Type {
	case operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC:
		if update.Snapshot != nil {
			err = c.handleSnapshot(ctx, update.Snapshot)
		}
	case operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT:
		// Heartbeat from server, no action needed
		c.logger.Debug("received heartbeat from operator")
	default:
		// Incremental update
		c.mu.RLock()
		handler := c.onConfigUpdate
		c.mu.RUnlock()

		if handler != nil {
			err = handler(ctx, update)
		}
	}

	duration := time.Since(startTime)
	c.metrics.observeConfigApplyDuration(duration.Seconds())

	if err != nil {
		c.metrics.incConfigUpdates(updateType, "error")
		span.RecordError(err)
		c.sendAcknowledgment(ctx, update.Version, false, err.Error(), duration)
		return err
	}

	c.metrics.incConfigUpdates(updateType, "success")

	// Update tracking
	c.mu.Lock()
	c.lastAppliedVersion = update.Version
	c.lastAppliedSequence = update.Sequence
	c.lastConfigAppliedAt = time.Now()
	c.mu.Unlock()

	c.metrics.setLastConfigVersion(update.Sequence)
	if update.Timestamp != nil {
		c.metrics.setLastConfigTimestamp(float64(update.Timestamp.AsTime().Unix()))
	} else {
		// For snapshots and updates without an explicit timestamp, use the
		// current time so the metric never stays at epoch 0 (1970-01-01).
		c.metrics.setLastConfigTimestamp(float64(time.Now().Unix()))
	}

	// Send acknowledgment
	c.sendAcknowledgment(ctx, update.Version, true, "", duration)

	return nil
}

// handleSnapshot processes a full configuration snapshot.
func (c *Client) handleSnapshot(ctx context.Context, snapshot *operatorv1alpha1.ConfigurationSnapshot) error {
	ctx, span := c.tracer.Start(ctx, "operator.HandleSnapshot",
		trace.WithAttributes(
			attribute.String("snapshot.version", snapshot.Version),
			attribute.Int("snapshot.total_resources", int(snapshot.TotalResources)),
		),
	)
	defer span.End()

	c.logger.Info("applying configuration snapshot",
		observability.String("version", snapshot.Version),
		observability.Int("total_resources", int(snapshot.TotalResources)),
		observability.String("checksum", snapshot.Checksum),
	)

	c.mu.RLock()
	handler := c.onSnapshot
	c.mu.RUnlock()

	if handler != nil {
		return handler(ctx, snapshot)
	}

	return nil
}

// sendAcknowledgment sends a configuration acknowledgment to the operator.
func (c *Client) sendAcknowledgment(
	ctx context.Context, version string, success bool, errMsg string, duration time.Duration,
) {
	ctx, span := c.tracer.Start(ctx, "operator.SendAcknowledgment")
	defer span.End()

	c.mu.RLock()
	sessionID := c.sessionID
	c.mu.RUnlock()

	req := &operatorv1alpha1.AcknowledgeConfigurationRequest{
		SessionId: sessionID,
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      c.config.GatewayName,
			Namespace: c.config.GatewayNamespace,
		},
		ConfigVersion: version,
		Success:       success,
		ErrorMessage:  errMsg,
		ApplyDuration: durationpb.New(duration),
	}

	cli := c.serviceClient()
	if cli == nil {
		c.logger.Warn("skipping configuration acknowledgment: no active connection",
			observability.String("version", version),
		)
		return
	}

	_, err := cli.AcknowledgeConfiguration(ctx, req)
	if err != nil {
		c.logger.Warn("failed to send configuration acknowledgment",
			observability.Error(err),
			observability.String("version", version),
		)
	}
}

// getHeartbeatInterval returns the heartbeat interval under the read lock.
// register() may update the interval from the server response while an older
// generation's goroutine is still draining, so lock-free reads would race.
func (c *Client) getHeartbeatInterval() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.heartbeatInterval
}

// runHeartbeatLoop runs the heartbeat loop.
//
// stopCh is the goroutine's own generation stop channel, captured at spawn
// time (generation capture pattern); see runStreamLoop for details.
func (c *Client) runHeartbeatLoop(ctx context.Context, stopCh <-chan struct{}) {
	ticker := time.NewTicker(c.getHeartbeatInterval())
	defer ticker.Stop()

	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if c.connected.Load() {
				c.sendHeartbeat(ctx)
			}
		}
	}
}

// sendHeartbeat sends a heartbeat to the operator.
func (c *Client) sendHeartbeat(ctx context.Context) {
	ctx, span := c.tracer.Start(ctx, "operator.Heartbeat")
	defer span.End()

	startTime := time.Now()

	c.mu.RLock()
	sessionID := c.sessionID
	lastVersion := c.lastAppliedVersion
	lastConfigApplied := c.lastConfigAppliedAt
	c.mu.RUnlock()

	status := c.buildGatewayStatus(lastConfigApplied)

	req := &operatorv1alpha1.HeartbeatRequest{
		SessionId: sessionID,
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      c.config.GatewayName,
			Namespace: c.config.GatewayNamespace,
		},
		Status:             status,
		LastAppliedVersion: lastVersion,
	}

	cli := c.serviceClient()
	if cli == nil {
		c.logger.Warn("skipping heartbeat: no active connection")
		return
	}

	resp, err := cli.Heartbeat(ctx, req)
	if err != nil {
		c.logger.Warn("heartbeat failed",
			observability.Error(err),
		)
		span.RecordError(err)
		return
	}

	latency := time.Since(startTime)
	c.metrics.observeHeartbeatLatency(latency.Seconds())

	if resp.ShouldReconnect {
		c.logger.Info("operator requested reconnection",
			observability.String("message", resp.Message),
		)
		// Trigger reconnection by closing the stream
		// The stream loop will handle reconnection
		c.connected.Store(false)
		c.metrics.setConnected(false)
	}

	c.logger.Debug("heartbeat sent",
		observability.Duration("latency", latency),
		observability.Bool("acknowledged", resp.Acknowledged),
	)
}

// buildGatewayStatus builds the gateway status for heartbeats.
func (c *Client) buildGatewayStatus(lastConfigApplied time.Time) *operatorv1alpha1.GatewayStatus {
	c.mu.RLock()
	startTime := c.startTime
	c.mu.RUnlock()

	status := &operatorv1alpha1.GatewayStatus{
		Health: operatorv1alpha1.HealthState_HEALTH_STATE_HEALTHY,
		Uptime: durationpb.New(time.Since(startTime)),
	}

	if !lastConfigApplied.IsZero() {
		status.LastConfigApplied = timestamppb.New(lastConfigApplied)
	}

	if c.statusProvider != nil {
		status.ActiveConnections = c.statusProvider.GetActiveConnections()
		status.RequestsPerSecond = c.statusProvider.GetRequestsPerSecond()
		status.ErrorRate = c.statusProvider.GetErrorRate()
		status.MemoryBytes = c.statusProvider.GetMemoryBytes()
		status.CpuUsage = c.statusProvider.GetCPUUsage()

		if !c.statusProvider.IsHealthy() {
			status.Health = operatorv1alpha1.HealthState_HEALTH_STATE_DEGRADED
		}
	}

	return status
}

// reconnectWithBackoff attempts to reconnect with exponential backoff.
//
// stopCh is the calling goroutine's generation stop channel, captured at
// spawn time (generation capture pattern); see runStreamLoop for details.
func (c *Client) reconnectWithBackoff(ctx context.Context, stopCh <-chan struct{}) bool {
	backoffCfg := c.config.ReconnectBackoff
	maxRetries := backoffCfg.GetMaxRetries()

	// Derive a context that is canceled when stopCh is closed so that
	// long-running RPCs (Connect, register) are interrupted promptly.
	reconnectCtx, reconnectCancel := context.WithCancel(ctx)
	defer reconnectCancel()

	go func() {
		select {
		case <-stopCh:
			reconnectCancel()
		case <-reconnectCtx.Done():
			// Context already canceled; nothing to do.
		}
	}()

	for {
		select {
		case <-stopCh:
			return false
		default:
		}

		attempt := int(c.reconnectAttempts.Add(1))
		c.metrics.incReconnects()

		// Check max retries (0 = unlimited)
		if maxRetries > 0 && attempt > maxRetries {
			c.logger.Error("max reconnection attempts reached",
				observability.Int("attempts", attempt),
				observability.Int("max_retries", maxRetries),
			)
			return false
		}

		// Calculate backoff
		backoff := c.calculateBackoff(attempt)

		c.logger.Info("reconnecting to operator",
			observability.Int("attempt", attempt),
			observability.Duration("backoff", backoff),
		)

		// Wait for backoff
		select {
		case <-stopCh:
			return false
		case <-time.After(backoff):
		}

		// Attempt reconnection
		if err := c.Connect(reconnectCtx); err != nil {
			c.logger.Error("reconnection failed",
				observability.Error(err),
				observability.Int("attempt", attempt),
			)
			continue
		}

		// Re-register
		if err := c.register(reconnectCtx); err != nil {
			// If the context was canceled due to stop signal, exit immediately
			if reconnectCtx.Err() != nil {
				return false
			}
			c.logger.Error("re-registration failed",
				observability.Error(err),
				observability.Int("attempt", attempt),
			)
			continue
		}

		// Success
		c.reconnectAttempts.Store(0)
		c.logger.Info("reconnected to operator successfully")
		return true
	}
}

// calculateBackoff calculates the backoff duration for the given attempt.
// The attempt number is passed explicitly so concurrent reconnect loops from
// different goroutine generations never share intermediate state.
func (c *Client) calculateBackoff(attempt int) time.Duration {
	backoffCfg := c.config.ReconnectBackoff
	initial := backoffCfg.GetInitialInterval()
	maxBackoff := backoffCfg.GetMaxInterval()
	multiplier := backoffCfg.GetMultiplier()

	// Exponential backoff: initial * multiplier^attempt
	backoff := float64(initial) * math.Pow(multiplier, float64(attempt-1))

	// Cap at max
	if backoff > float64(maxBackoff) {
		backoff = float64(maxBackoff)
	}

	return time.Duration(backoff)
}

// GetConfiguration fetches the current configuration snapshot from the operator.
func (c *Client) GetConfiguration(ctx context.Context) (*operatorv1alpha1.ConfigurationSnapshot, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	ctx, span := c.tracer.Start(ctx, "operator.GetConfiguration")
	defer span.End()

	c.mu.RLock()
	sessionID := c.sessionID
	c.mu.RUnlock()

	req := &operatorv1alpha1.GetConfigurationRequest{
		SessionId: sessionID,
		Gateway: &operatorv1alpha1.GatewayInfo{
			Name:      c.config.GatewayName,
			Namespace: c.config.GatewayNamespace,
		},
		Namespaces: c.config.Namespaces,
	}

	cli := c.serviceClient()
	if cli == nil {
		span.RecordError(ErrNotConnected)
		return nil, ErrNotConnected
	}

	resp, err := cli.GetConfiguration(ctx, req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get configuration: %w", err)
	}

	return resp, nil
}

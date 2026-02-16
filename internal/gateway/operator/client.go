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
	stopCh              chan struct{}
	stoppedCh           chan struct{}
	wg                  sync.WaitGroup // WaitGroup for goroutine coordination
	reconnectAttempts   int

	// Callbacks
	onConfigUpdate ConfigUpdateHandler
	onSnapshot     SnapshotHandler

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
func (c *Client) Start(ctx context.Context) error {
	if !c.started.CompareAndSwap(false, true) {
		return ErrAlreadyStarted
	}

	ctx, span := c.tracer.Start(ctx, "operator.Start")
	defer span.End()

	c.startTime = time.Now()
	c.stopCh = make(chan struct{})
	c.stoppedCh = make(chan struct{})

	// Connect if not already connected
	if c.conn == nil {
		if err := c.Connect(ctx); err != nil {
			c.started.Store(false)
			span.RecordError(err)
			return err
		}
	}

	// Register with operator
	if err := c.register(ctx); err != nil {
		c.started.Store(false)
		span.RecordError(err)
		return err
	}

	// Start background goroutines with WaitGroup coordination
	c.wg.Add(2)
	go func() {
		defer c.wg.Done()
		c.runStreamLoop(ctx)
	}()
	go func() {
		defer c.wg.Done()
		c.runHeartbeatLoop(ctx)
	}()

	c.logger.Info("operator client started",
		observability.String("session_id", c.sessionID),
		observability.String("gateway_name", c.config.GatewayName),
		observability.String("gateway_namespace", c.config.GatewayNamespace),
	)

	return nil
}

// Stop gracefully stops the client.
func (c *Client) Stop() error {
	if !c.started.CompareAndSwap(true, false) {
		return ErrNotStarted
	}

	c.logger.Info("stopping operator client")

	// Signal stop
	close(c.stopCh)

	// Wait for goroutines to finish with timeout using WaitGroup
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines stopped cleanly
		c.logger.Debug("all operator client goroutines stopped")
	case <-time.After(clientStopTimeout):
		c.logger.Warn("timeout waiting for operator client goroutines to stop")
	}

	// Signal stoppedCh for any external waiters
	select {
	case <-c.stoppedCh:
		// Already closed
	default:
		close(c.stoppedCh)
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

	resp, err := c.client.RegisterGateway(ctx, req)
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
	c.mu.Unlock()

	c.connected.Store(true)
	c.metrics.setConnected(true)

	span.SetAttributes(attribute.String("session_id", resp.SessionId))

	c.logger.Info("gateway registered successfully",
		observability.String("session_id", resp.SessionId),
		observability.Duration("heartbeat_interval", c.heartbeatInterval),
	)

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
func (c *Client) runStreamLoop(ctx context.Context) {
	// Note: WaitGroup.Done() is called by the parent goroutine wrapper in Start()
	// stoppedCh is now managed by Stop() method for proper coordination

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		if err := c.streamConfiguration(ctx); err != nil {
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
			if !c.reconnectWithBackoff(ctx) {
				return
			}
		}
	}
}

// streamConfiguration establishes and handles the configuration stream.
func (c *Client) streamConfiguration(ctx context.Context) error {
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

	stream, err := c.client.StreamConfiguration(ctx, req)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to start configuration stream: %w", err)
	}

	c.logger.Info("configuration stream established",
		observability.String("session_id", sessionID),
	)

	for {
		select {
		case <-c.stopCh:
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

	_, err := c.client.AcknowledgeConfiguration(ctx, req)
	if err != nil {
		c.logger.Warn("failed to send configuration acknowledgment",
			observability.Error(err),
			observability.String("version", version),
		)
	}
}

// runHeartbeatLoop runs the heartbeat loop.
func (c *Client) runHeartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
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

	resp, err := c.client.Heartbeat(ctx, req)
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
	status := &operatorv1alpha1.GatewayStatus{
		Health: operatorv1alpha1.HealthState_HEALTH_STATE_HEALTHY,
		Uptime: durationpb.New(time.Since(c.startTime)),
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
func (c *Client) reconnectWithBackoff(ctx context.Context) bool {
	backoffCfg := c.config.ReconnectBackoff
	maxRetries := backoffCfg.GetMaxRetries()

	for {
		select {
		case <-c.stopCh:
			return false
		default:
		}

		c.reconnectAttempts++
		c.metrics.incReconnects()

		// Check max retries (0 = unlimited)
		if maxRetries > 0 && c.reconnectAttempts > maxRetries {
			c.logger.Error("max reconnection attempts reached",
				observability.Int("attempts", c.reconnectAttempts),
				observability.Int("max_retries", maxRetries),
			)
			return false
		}

		// Calculate backoff
		backoff := c.calculateBackoff()

		c.logger.Info("reconnecting to operator",
			observability.Int("attempt", c.reconnectAttempts),
			observability.Duration("backoff", backoff),
		)

		// Wait for backoff
		select {
		case <-c.stopCh:
			return false
		case <-time.After(backoff):
		}

		// Attempt reconnection
		if err := c.Connect(ctx); err != nil {
			c.logger.Error("reconnection failed",
				observability.Error(err),
				observability.Int("attempt", c.reconnectAttempts),
			)
			continue
		}

		// Re-register
		if err := c.register(ctx); err != nil {
			c.logger.Error("re-registration failed",
				observability.Error(err),
				observability.Int("attempt", c.reconnectAttempts),
			)
			continue
		}

		// Success
		c.reconnectAttempts = 0
		c.logger.Info("reconnected to operator successfully")
		return true
	}
}

// calculateBackoff calculates the backoff duration for the current attempt.
func (c *Client) calculateBackoff() time.Duration {
	backoffCfg := c.config.ReconnectBackoff
	initial := backoffCfg.GetInitialInterval()
	maxBackoff := backoffCfg.GetMaxInterval()
	multiplier := backoffCfg.GetMultiplier()

	// Exponential backoff: initial * multiplier^attempt
	backoff := float64(initial) * math.Pow(multiplier, float64(c.reconnectAttempts-1))

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

	resp, err := c.client.GetConfiguration(ctx, req)
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get configuration: %w", err)
	}

	return resp, nil
}

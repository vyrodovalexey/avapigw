// Package grpc provides gRPC server and client for operator-gateway communication.
package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"

	"github.com/vyrodovalexey/avapigw/internal/observability"
	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// tracerName is the OpenTelemetry tracer name for gRPC service operations.
const tracerName = "avapigw-operator/grpc"

// defaultHeartbeatInterval is the recommended heartbeat interval sent to gateways.
const defaultHeartbeatInterval = 30 * time.Second

// configurationServiceImpl implements the protobuf ConfigurationServiceServer interface.
// It delegates to the Server's in-memory configuration maps.
type configurationServiceImpl struct {
	operatorv1alpha1.UnimplementedConfigurationServiceServer
	server        *Server
	tracer        trace.Tracer
	configVersion atomic.Int64 // monotonically increasing configuration version, per-instance to avoid test leaks
}

// registerConfigurationService registers the protobuf ConfigurationService with the gRPC server.
func registerConfigurationService(grpcSrv *grpc.Server, s *Server) {
	svc := &configurationServiceImpl{
		server: s,
		tracer: otel.Tracer(tracerName),
	}
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcSrv, svc)
	s.logger.Info("registered ConfigurationService with gRPC server")
}

// RegisterGateway registers a gateway instance with the operator and returns the initial configuration snapshot.
func (svc *configurationServiceImpl) RegisterGateway(
	ctx context.Context,
	req *operatorv1alpha1.RegisterGatewayRequest,
) (*operatorv1alpha1.RegisterGatewayResponse, error) {
	ctx, span := svc.tracer.Start(ctx, "ConfigurationService.RegisterGateway",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		svc.server.metrics.requestDuration.WithLabelValues("RegisterGateway").Observe(time.Since(start).Seconds())
	}()

	if req.GetGateway() == nil {
		svc.server.metrics.requestsTotal.WithLabelValues("RegisterGateway", "invalid_argument").Inc()
		return &operatorv1alpha1.RegisterGatewayResponse{
			Success:      false,
			ErrorMessage: "gateway info is required",
		}, nil
	}

	gw := req.GetGateway()
	span.SetAttributes(
		attribute.String("gateway.name", gw.GetName()),
		attribute.String("gateway.namespace", gw.GetNamespace()),
	)

	sessionID := uuid.New().String()
	svc.server.RegisterGateway(gw.GetName(), gw.GetNamespace())

	snapshot, err := svc.buildSnapshot(ctx)
	if err != nil {
		svc.server.metrics.requestsTotal.WithLabelValues("RegisterGateway", "error").Inc()
		svc.server.logger.Error("failed to build configuration snapshot",
			observability.Error(err),
		)
		return &operatorv1alpha1.RegisterGatewayResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to build configuration snapshot: %v", err),
		}, nil
	}

	svc.server.metrics.requestsTotal.WithLabelValues("RegisterGateway", "ok").Inc()
	svc.server.logger.Info("gateway registered via gRPC",
		observability.String("name", gw.GetName()),
		observability.String("namespace", gw.GetNamespace()),
		observability.String("session_id", sessionID),
	)

	return &operatorv1alpha1.RegisterGatewayResponse{
		Success:           true,
		SessionId:         sessionID,
		InitialConfig:     snapshot,
		HeartbeatInterval: durationpb.New(defaultHeartbeatInterval),
	}, nil
}

// GetConfiguration returns the current configuration snapshot.
func (svc *configurationServiceImpl) GetConfiguration(
	ctx context.Context,
	req *operatorv1alpha1.GetConfigurationRequest,
) (*operatorv1alpha1.ConfigurationSnapshot, error) {
	ctx, span := svc.tracer.Start(ctx, "ConfigurationService.GetConfiguration",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		svc.server.metrics.requestDuration.WithLabelValues("GetConfiguration").Observe(time.Since(start).Seconds())
	}()

	if req.GetGateway() != nil {
		span.SetAttributes(
			attribute.String("gateway.name", req.GetGateway().GetName()),
			attribute.String("gateway.namespace", req.GetGateway().GetNamespace()),
		)
	}

	snapshot, err := svc.buildSnapshot(ctx)
	if err != nil {
		svc.server.metrics.requestsTotal.WithLabelValues("GetConfiguration", "error").Inc()
		return nil, fmt.Errorf("failed to build configuration snapshot: %w", err)
	}

	svc.server.metrics.requestsTotal.WithLabelValues("GetConfiguration", "ok").Inc()
	return snapshot, nil
}

// Heartbeat sends a keep-alive signal to the operator.
func (svc *configurationServiceImpl) Heartbeat(
	ctx context.Context,
	req *operatorv1alpha1.HeartbeatRequest,
) (*operatorv1alpha1.HeartbeatResponse, error) {
	_, span := svc.tracer.Start(ctx, "ConfigurationService.Heartbeat",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		svc.server.metrics.requestDuration.WithLabelValues("Heartbeat").Observe(time.Since(start).Seconds())
	}()

	if req.GetGateway() != nil {
		gw := req.GetGateway()
		span.SetAttributes(
			attribute.String("gateway.name", gw.GetName()),
			attribute.String("gateway.namespace", gw.GetNamespace()),
		)
		svc.server.UpdateGatewayHeartbeat(gw.GetName(), gw.GetNamespace())
	}

	svc.server.metrics.requestsTotal.WithLabelValues("Heartbeat", "ok").Inc()

	return &operatorv1alpha1.HeartbeatResponse{
		Acknowledged: true,
		ServerTime:   timestamppb.Now(),
	}, nil
}

// AcknowledgeConfiguration acknowledges receipt and application of a configuration update.
func (svc *configurationServiceImpl) AcknowledgeConfiguration(
	ctx context.Context,
	req *operatorv1alpha1.AcknowledgeConfigurationRequest,
) (*operatorv1alpha1.AcknowledgeConfigurationResponse, error) {
	_, span := svc.tracer.Start(ctx, "ConfigurationService.AcknowledgeConfiguration",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	start := time.Now()
	defer func() {
		svc.server.metrics.requestDuration.
			WithLabelValues("AcknowledgeConfiguration").
			Observe(time.Since(start).Seconds())
	}()

	if req.GetGateway() != nil {
		span.SetAttributes(
			attribute.String("gateway.name", req.GetGateway().GetName()),
			attribute.String("gateway.namespace", req.GetGateway().GetNamespace()),
			attribute.String("config_version", req.GetConfigVersion()),
			attribute.Bool("success", req.GetSuccess()),
		)
	}

	result := "success"
	if !req.GetSuccess() {
		result = "failure"
		svc.server.logger.Warn("gateway failed to apply configuration",
			observability.String("session_id", req.GetSessionId()),
			observability.String("config_version", req.GetConfigVersion()),
			observability.String("error", req.GetErrorMessage()),
		)
	}

	svc.server.metrics.requestsTotal.WithLabelValues("AcknowledgeConfiguration", result).Inc()

	return &operatorv1alpha1.AcknowledgeConfigurationResponse{
		Received:   true,
		ServerTime: timestamppb.Now(),
	}, nil
}

// StreamConfiguration establishes a server-side streaming connection for receiving configuration updates.
func (svc *configurationServiceImpl) StreamConfiguration(
	req *operatorv1alpha1.StreamConfigurationRequest,
	stream grpc.ServerStreamingServer[operatorv1alpha1.ConfigurationUpdate],
) error {
	ctx := stream.Context()
	_, span := svc.tracer.Start(ctx, "ConfigurationService.StreamConfiguration",
		trace.WithSpanKind(trace.SpanKindServer),
	)
	defer span.End()

	if req.GetGateway() != nil {
		span.SetAttributes(
			attribute.String("gateway.name", req.GetGateway().GetName()),
			attribute.String("gateway.namespace", req.GetGateway().GetNamespace()),
		)
	}

	svc.server.metrics.requestsTotal.WithLabelValues("StreamConfiguration", "started").Inc()

	// Send initial full sync
	snapshot, err := svc.buildSnapshot(ctx)
	if err != nil {
		svc.server.metrics.requestsTotal.WithLabelValues("StreamConfiguration", "error").Inc()
		return fmt.Errorf("failed to build initial snapshot: %w", err)
	}

	version := fmt.Sprintf("%d", svc.configVersion.Add(1))
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:      operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC,
		Version:   version,
		Timestamp: timestamppb.Now(),
		Snapshot:  snapshot,
	}

	if err := stream.Send(update); err != nil {
		svc.server.metrics.requestsTotal.WithLabelValues("StreamConfiguration", "send_error").Inc()
		return fmt.Errorf("failed to send initial snapshot: %w", err)
	}

	// Watch for configuration changes and push updates to the stream.
	// The broadcast pattern uses a channel that is closed on each config change,
	// waking all waiting goroutines. A new channel is created for the next cycle.
	for {
		waitCh := svc.server.WaitForConfigChange()
		select {
		case <-ctx.Done():
			svc.server.metrics.requestsTotal.WithLabelValues("StreamConfiguration", "completed").Inc()
			svc.server.logger.Info("configuration stream closed",
				observability.String("session_id", req.GetSessionId()),
			)
			return nil
		case <-waitCh:
			// Configuration changed, build and send a new snapshot
			snapshot, err = svc.buildSnapshot(ctx)
			if err != nil {
				svc.server.logger.Error("failed to build snapshot for stream update", observability.Error(err))
				continue
			}

			version = fmt.Sprintf("%d", svc.configVersion.Add(1))
			update = &operatorv1alpha1.ConfigurationUpdate{
				Type:      operatorv1alpha1.UpdateType_UPDATE_TYPE_FULL_SYNC,
				Version:   version,
				Timestamp: timestamppb.Now(),
				Snapshot:  snapshot,
			}

			if err := stream.Send(update); err != nil {
				svc.server.metrics.requestsTotal.WithLabelValues("StreamConfiguration", "send_error").Inc()
				return fmt.Errorf("failed to send configuration update: %w", err)
			}

			svc.server.logger.Info("configuration update sent to gateway",
				observability.String("version", version),
				observability.Int("total_resources", int(snapshot.TotalResources)),
			)
		}
	}
}

// buildSnapshot builds a ConfigurationSnapshot from the server's in-memory maps.
func (svc *configurationServiceImpl) buildSnapshot(
	ctx context.Context,
) (*operatorv1alpha1.ConfigurationSnapshot, error) {
	_, span := svc.tracer.Start(ctx, "ConfigurationService.buildSnapshot")
	defer span.End()

	svc.server.mu.RLock()
	defer svc.server.mu.RUnlock()

	snapshot := &operatorv1alpha1.ConfigurationSnapshot{
		Version:   fmt.Sprintf("%d", svc.configVersion.Load()),
		Timestamp: timestamppb.Now(),
	}

	// Build API routes
	for key, data := range svc.server.apiRoutes {
		resource := buildConfigResource(operatorv1alpha1.ResourceType_RESOURCE_TYPE_API_ROUTE, key, data)
		snapshot.ApiRoutes = append(snapshot.ApiRoutes, resource)
	}

	// Build gRPC routes
	for key, data := range svc.server.grpcRoutes {
		resource := buildConfigResource(operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_ROUTE, key, data)
		snapshot.GrpcRoutes = append(snapshot.GrpcRoutes, resource)
	}

	// Build backends
	for key, data := range svc.server.backends {
		resource := buildConfigResource(operatorv1alpha1.ResourceType_RESOURCE_TYPE_BACKEND, key, data)
		snapshot.Backends = append(snapshot.Backends, resource)
	}

	// Build gRPC backends
	for key, data := range svc.server.grpcBackends {
		resource := buildConfigResource(operatorv1alpha1.ResourceType_RESOURCE_TYPE_GRPC_BACKEND, key, data)
		snapshot.GrpcBackends = append(snapshot.GrpcBackends, resource)
	}

	totalResources := len(snapshot.ApiRoutes) + len(snapshot.GrpcRoutes) +
		len(snapshot.Backends) + len(snapshot.GrpcBackends)
	snapshot.TotalResources = int32(totalResources) //nolint:gosec // resource count is bounded by cluster size

	checksum, err := computeSnapshotChecksum(snapshot)
	if err != nil {
		svc.server.logger.Error("failed to compute snapshot checksum", observability.Error(err))
		return nil, fmt.Errorf("failed to compute snapshot checksum: %w", err)
	}
	snapshot.Checksum = checksum

	span.SetAttributes(attribute.Int("total_resources", totalResources))

	return snapshot, nil
}

// buildConfigResource creates a ConfigurationResource from a key and JSON data.
func buildConfigResource(
	resourceType operatorv1alpha1.ResourceType,
	key string,
	data []byte,
) *operatorv1alpha1.ConfigurationResource {
	return &operatorv1alpha1.ConfigurationResource{
		Type:     resourceType,
		Name:     key,
		SpecJson: data,
	}
}

// computeSnapshotChecksum computes a SHA-256 checksum of the snapshot for validation.
// It excludes the Timestamp field to ensure deterministic checksums for identical configurations.
// An error is returned if JSON marshaling fails so callers can handle it explicitly.
func computeSnapshotChecksum(snapshot *operatorv1alpha1.ConfigurationSnapshot) (string, error) {
	if snapshot == nil {
		data, err := json.Marshal(nil)
		if err != nil {
			return "", fmt.Errorf("marshal nil snapshot: %w", err)
		}
		hash := sha256.Sum256(data)
		return fmt.Sprintf("%x", hash), nil
	}

	// Create a copy with the timestamp zeroed out so that identical configs
	// always produce the same checksum regardless of when they were built.
	stable := &operatorv1alpha1.ConfigurationSnapshot{
		Version:        snapshot.Version,
		ApiRoutes:      snapshot.ApiRoutes,
		GrpcRoutes:     snapshot.GrpcRoutes,
		Backends:       snapshot.Backends,
		GrpcBackends:   snapshot.GrpcBackends,
		TotalResources: snapshot.TotalResources,
		Checksum:       snapshot.Checksum,
		// Timestamp intentionally omitted to ensure deterministic checksums
	}

	data, err := json.Marshal(stable)
	if err != nil {
		return "", fmt.Errorf("marshal snapshot: %w", err)
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

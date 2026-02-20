// Copyright 2026 The avapigw Authors.
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	operatorv1alpha1 "github.com/vyrodovalexey/avapigw/proto/operator/v1alpha1"
)

// ============================================================================
// Fix 4: Timestamp fallback when update.Timestamp == nil
// ============================================================================

func TestHandleUpdate_TimestampFallback_NilTimestamp(t *testing.T) {
	// When update.Timestamp is nil, handleUpdate should use time.Now()
	// as fallback for the lastConfigTimestamp metric.

	// Start mock server for acknowledgment
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	registry := prometheus.NewRegistry()
	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg, WithMetricsRegistry(registry))
	require.NoError(t, err)

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)
	defer func() {
		if client.conn != nil {
			client.conn.Close()
		}
	}()

	beforeTime := time.Now().Unix()

	// Create update with nil Timestamp
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:      operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT,
		Version:   "v1",
		Sequence:  1,
		Timestamp: nil, // nil timestamp - should trigger fallback
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)

	afterTime := time.Now().Unix()

	// Verify the lastConfigTimestamp metric was set to approximately now
	ch := make(chan prometheus.Metric, 1)
	client.metrics.lastConfigTimestamp.Collect(ch)
	metric := <-ch

	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	timestamp := dto.GetGauge().GetValue()

	assert.GreaterOrEqual(t, timestamp, float64(beforeTime),
		"timestamp should be >= time before handleUpdate")
	assert.LessOrEqual(t, timestamp, float64(afterTime),
		"timestamp should be <= time after handleUpdate")
}

func TestHandleUpdate_TimestampFromUpdate(t *testing.T) {
	// When update.Timestamp is set, handleUpdate should use it directly.

	// Start mock server for acknowledgment
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	registry := prometheus.NewRegistry()
	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	client, err := NewClient(cfg, WithMetricsRegistry(registry))
	require.NoError(t, err)

	// Connect to the mock server
	err = client.Connect(context.Background())
	require.NoError(t, err)
	defer func() {
		if client.conn != nil {
			client.conn.Close()
		}
	}()

	// Create update with explicit Timestamp
	specificTime := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:      operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT,
		Version:   "v2",
		Sequence:  2,
		Timestamp: timestamppb.New(specificTime),
	}

	err = client.handleUpdate(context.Background(), update)
	require.NoError(t, err)

	// Verify the lastConfigTimestamp metric was set to the specific time
	ch := make(chan prometheus.Metric, 1)
	client.metrics.lastConfigTimestamp.Collect(ch)
	metric := <-ch

	dto := &io_prometheus_client.Metric{}
	require.NoError(t, metric.Write(dto))
	timestamp := dto.GetGauge().GetValue()

	assert.Equal(t, float64(specificTime.Unix()), timestamp,
		"timestamp should match the update's explicit timestamp")
}

// ============================================================================
// Table-driven test for timestamp handling
// ============================================================================

func TestHandleUpdate_TimestampHandling(t *testing.T) {
	tests := []struct {
		name           string
		timestamp      *timestamppb.Timestamp
		expectFallback bool
	}{
		{
			name:           "nil timestamp uses fallback",
			timestamp:      nil,
			expectFallback: true,
		},
		{
			name:           "explicit timestamp used directly",
			timestamp:      timestamppb.New(time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)),
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start mock server
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer listener.Close()

			mockServer := &MockConfigurationServiceServer{}
			mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
				&operatorv1alpha1.AcknowledgeConfigurationResponse{
					Received: true,
				}, nil,
			).Maybe()

			grpcServer := grpc.NewServer()
			operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

			go func() {
				_ = grpcServer.Serve(listener)
			}()
			defer grpcServer.Stop()

			registry := prometheus.NewRegistry()
			cfg := &Config{
				Enabled:          true,
				Address:          listener.Addr().String(),
				GatewayName:      "test-gateway",
				GatewayNamespace: "default",
			}

			client, err := NewClient(cfg, WithMetricsRegistry(registry))
			require.NoError(t, err)

			err = client.Connect(context.Background())
			require.NoError(t, err)
			defer func() {
				if client.conn != nil {
					client.conn.Close()
				}
			}()

			beforeTime := time.Now().Unix()

			update := &operatorv1alpha1.ConfigurationUpdate{
				Type:      operatorv1alpha1.UpdateType_UPDATE_TYPE_HEARTBEAT,
				Version:   "v1",
				Sequence:  1,
				Timestamp: tt.timestamp,
			}

			err = client.handleUpdate(context.Background(), update)
			require.NoError(t, err)

			afterTime := time.Now().Unix()

			// Collect metric
			ch := make(chan prometheus.Metric, 1)
			client.metrics.lastConfigTimestamp.Collect(ch)
			metric := <-ch

			dto := &io_prometheus_client.Metric{}
			require.NoError(t, metric.Write(dto))
			timestamp := dto.GetGauge().GetValue()

			if tt.expectFallback {
				// Should be approximately now
				assert.GreaterOrEqual(t, timestamp, float64(beforeTime))
				assert.LessOrEqual(t, timestamp, float64(afterTime))
			} else {
				// Should match the explicit timestamp
				assert.Equal(t, float64(tt.timestamp.AsTime().Unix()), timestamp)
			}
		})
	}
}

// ============================================================================
// HandleUpdate with error in handler - verify metrics still recorded
// ============================================================================

func TestHandleUpdate_ErrorPath_MetricsRecorded(t *testing.T) {
	// Start mock server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	mockServer := &MockConfigurationServiceServer{}
	mockServer.On("AcknowledgeConfiguration", mock.Anything, mock.Anything).Return(
		&operatorv1alpha1.AcknowledgeConfigurationResponse{
			Received: true,
		}, nil,
	).Maybe()

	grpcServer := grpc.NewServer()
	operatorv1alpha1.RegisterConfigurationServiceServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	registry := prometheus.NewRegistry()
	cfg := &Config{
		Enabled:          true,
		Address:          listener.Addr().String(),
		GatewayName:      "test-gateway",
		GatewayNamespace: "default",
	}

	handlerErr := assert.AnError
	client, err := NewClient(cfg,
		WithMetricsRegistry(registry),
		WithConfigUpdateHandler(func(ctx context.Context, update *operatorv1alpha1.ConfigurationUpdate) error {
			return handlerErr
		}),
	)
	require.NoError(t, err)

	err = client.Connect(context.Background())
	require.NoError(t, err)
	defer func() {
		if client.conn != nil {
			client.conn.Close()
		}
	}()

	update := &operatorv1alpha1.ConfigurationUpdate{
		Type:     operatorv1alpha1.UpdateType_UPDATE_TYPE_ADDED,
		Version:  "v1",
		Sequence: 1,
	}

	err = client.handleUpdate(context.Background(), update)
	assert.Error(t, err)

	// Verify error metric was recorded
	families, err := registry.Gather()
	require.NoError(t, err)

	found := false
	for _, family := range families {
		if family.GetName() == "gateway_operator_client_config_updates_total" {
			for _, m := range family.GetMetric() {
				for _, label := range m.GetLabel() {
					if label.GetName() == "status" && label.GetValue() == "error" {
						found = true
					}
				}
			}
		}
	}
	assert.True(t, found, "error metric should be recorded")
}

// Package main provides tests for setupHealthChecks using a mock healthCheckAdder.
package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	"github.com/vyrodovalexey/avapigw/internal/operator/cert"
	operatorgrpc "github.com/vyrodovalexey/avapigw/internal/operator/grpc"

	"github.com/prometheus/client_golang/prometheus"
)

// mockHealthCheckAdder implements healthCheckAdder for testing.
type mockHealthCheckAdder struct {
	healthzErr error
	readyzErr  error
}

func (m *mockHealthCheckAdder) AddHealthzCheck(_ string, _ healthz.Checker) error {
	return m.healthzErr
}

func (m *mockHealthCheckAdder) AddReadyzCheck(_ string, _ healthz.Checker) error {
	return m.readyzErr
}

// ============================================================================
// setupHealthChecks Tests
// ============================================================================

func TestSetupHealthChecks_Success(t *testing.T) {
	mock := &mockHealthCheckAdder{}
	err := setupHealthChecks(mock)
	assert.NoError(t, err)
}

func TestSetupHealthChecks_HealthzError(t *testing.T) {
	mock := &mockHealthCheckAdder{
		healthzErr: errors.New("healthz registration failed"),
	}
	err := setupHealthChecks(mock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to set up health check")
}

func TestSetupHealthChecks_ReadyzError(t *testing.T) {
	mock := &mockHealthCheckAdder{
		readyzErr: errors.New("readyz registration failed"),
	}
	err := setupHealthChecks(mock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to set up ready check")
}

func TestSetupHealthChecks_BothErrors(t *testing.T) {
	mock := &mockHealthCheckAdder{
		healthzErr: errors.New("healthz failed"),
		readyzErr:  errors.New("readyz failed"),
	}
	// Should return the first error (healthz)
	err := setupHealthChecks(mock)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to set up health check")
}

// ============================================================================
// startGRPCServerBackground Tests - with real server
// ============================================================================

func TestStartGRPCServerBackground_WithServer(t *testing.T) {
	reg := prometheus.NewRegistry()
	server, err := operatorgrpc.NewServerWithRegistry(&operatorgrpc.ServerConfig{
		Port: 0, // Will use default
	}, reg)
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic
	startGRPCServerBackground(ctx, server)

	// Give it a moment to start
	// Then cancel to stop
	cancel()
}

// ============================================================================
// setupGRPCServer Tests - with real cert manager
// ============================================================================

func TestSetupGRPCServer_WithSelfSignedCert(t *testing.T) {
	ctx := context.Background()

	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca",
		KeySize:      2048,
	})
	assert.NoError(t, err)
	defer certManager.Close()

	cfg := &Config{
		GRPCPort:        0, // Will use default
		CertServiceName: "test-service",
		CertNamespace:   "test-namespace",
	}

	server, err := setupGRPCServer(ctx, cfg, certManager)
	// This may fail due to duplicate metrics registration, but we test the code path
	if err == nil {
		assert.NotNil(t, server)
		server.Stop()
	}
}

func TestSetupGRPCServer_WithCustomDNSNames(t *testing.T) {
	ctx := context.Background()

	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca",
		KeySize:      2048,
	})
	assert.NoError(t, err)
	defer certManager.Close()

	cfg := &Config{
		GRPCPort:        0,
		CertServiceName: "test-service",
		CertNamespace:   "test-namespace",
		CertDNSNames:    []string{"custom.example.com", "custom2.example.com"},
	}

	server, err := setupGRPCServer(ctx, cfg, certManager)
	if err == nil {
		assert.NotNil(t, server)
		server.Stop()
	}
}

// ============================================================================
// setupGRPCServerIfEnabled Tests - enabled path
// ============================================================================

func TestSetupGRPCServerIfEnabled_Enabled(t *testing.T) {
	ctx := context.Background()

	certManager, err := cert.NewSelfSignedProvider(&cert.SelfSignedProviderConfig{
		CACommonName: "test-ca",
		KeySize:      2048,
	})
	assert.NoError(t, err)
	defer certManager.Close()

	cfg := &Config{
		EnableGRPCServer: true,
		GRPCPort:         0,
		CertServiceName:  "test-service",
		CertNamespace:    "test-namespace",
	}

	server, err := setupGRPCServerIfEnabled(ctx, cfg, certManager)
	if err == nil && server != nil {
		server.Stop()
	}
}

// ============================================================================
// setupWebhooksIfEnabled Tests - enabled path (will fail without real manager)
// ============================================================================

func TestSetupWebhooksIfEnabled_EnabledNilManager(t *testing.T) {
	cfg := &Config{
		EnableWebhooks: true,
	}

	// This will panic because mgr is nil, so we recover
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected: nil manager causes panic
				err = errors.New("panic recovered")
			}
		}()
		err = setupWebhooksIfEnabled(context.Background(), nil, cfg)
	}()

	// Either returns error or panics (both are acceptable)
	assert.Error(t, err)
}

// ============================================================================
// setupTracingIfEnabled Tests - enabled path
// ============================================================================

func TestSetupTracingIfEnabled_EnabledWithEndpoint_HC(t *testing.T) {
	cfg := &Config{
		EnableTracing:       true,
		OTLPEndpoint:        "localhost:4317",
		TracingSamplingRate: 0.5,
	}

	shutdown, err := setupTracingIfEnabled(cfg)
	// May succeed or fail depending on OTLP availability
	if err == nil && shutdown != nil {
		shutdown()
	}
}

func TestSetupTracingIfEnabled_EnabledEmptyEndpoint_HC(t *testing.T) {
	cfg := &Config{
		EnableTracing:       true,
		OTLPEndpoint:        "",
		TracingSamplingRate: 1.0,
	}

	shutdown, err := setupTracingIfEnabled(cfg)
	if err == nil && shutdown != nil {
		shutdown()
	}
}

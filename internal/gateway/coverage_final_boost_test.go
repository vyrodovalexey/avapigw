// Package gateway provides additional tests to push coverage above 90%.
// This file targets uncovered paths in:
//   - listener.go: installTLSConnectionMetrics, Stop (TLS manager paths)
//   - grpc_listener.go: configureTLSFromConfig, handleTLSManagerCreationError, Stop
//   - gateway.go: cleanupListenersOnError, createGRPCListener
//   - route_middleware.go: buildMiddlewareChain (security, CORS, body limit, headers, transform, encoding)
package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	tlspkg "github.com/vyrodovalexey/avapigw/internal/tls"
)

// ============================================================================
// installTLSConnectionMetrics tests
// ============================================================================

func TestInstallTLSConnectionMetrics_NilTLSConfig(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Manually set up server without TLS config
	listener.server = &http.Server{}
	listener.tlsMetrics = tlspkg.NewNopMetrics()

	// Should return early without panic (TLSConfig is nil)
	listener.installTLSConnectionMetrics()
}

func TestInstallTLSConnectionMetrics_NilMetrics(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Set up server with TLS config but nil metrics
	listener.server = &http.Server{
		TLSConfig: &tls.Config{},
	}
	listener.tlsMetrics = nil

	// Should return early without panic (metrics is nil)
	listener.installTLSConnectionMetrics()
}

func TestInstallTLSConnectionMetrics_WithTLSConfigAndMetrics(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	metrics := tlspkg.NewNopMetrics()
	listener.server = &http.Server{
		TLSConfig: &tls.Config{},
	}
	listener.tlsMetrics = metrics

	// Should install the VerifyConnection callback
	listener.installTLSConnectionMetrics()

	// Verify the callback was installed
	require.NotNil(t, listener.server.TLSConfig.VerifyConnection)

	// Call the callback to exercise the code path (simple mode - no peer certs)
	err = listener.server.TLSConfig.VerifyConnection(tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_256_GCM_SHA384,
	})
	assert.NoError(t, err)
}

func TestInstallTLSConnectionMetrics_WithPeerCerts(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	metrics := tlspkg.NewNopMetrics()
	listener.server = &http.Server{
		TLSConfig: &tls.Config{},
	}
	listener.tlsMetrics = metrics

	listener.installTLSConnectionMetrics()

	// Call with peer certificates (mutual TLS mode)
	err = listener.server.TLSConfig.VerifyConnection(tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		PeerCertificates: []*x509.Certificate{{}},
	})
	assert.NoError(t, err)
}

func TestInstallTLSConnectionMetrics_WithOrigVerify(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	listener, err := NewListener(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	metrics := tlspkg.NewNopMetrics()
	origVerifyCalled := false
	listener.server = &http.Server{
		TLSConfig: &tls.Config{
			VerifyConnection: func(_ tls.ConnectionState) error {
				origVerifyCalled = true
				return nil
			},
		},
	}
	listener.tlsMetrics = metrics

	listener.installTLSConnectionMetrics()

	// Call the callback - should also call original VerifyConnection
	err = listener.server.TLSConfig.VerifyConnection(tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_256_GCM_SHA384,
	})
	assert.NoError(t, err)
	assert.True(t, origVerifyCalled, "original VerifyConnection should be called")
}

// ============================================================================
// Listener.Stop with route TLS manager
// ============================================================================

func TestListener_Stop_WithRouteTLSManager_ClosePath(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	routeTLSManager := tlspkg.NewRouteTLSManager()

	listener, err := NewListener(cfg, handler, WithRouteTLSManager(routeTLSManager))
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Stop should close the route TLS manager
	err = listener.Stop(ctx)
	require.NoError(t, err)
}

// ============================================================================
// Listener.Start with route TLS manager
// ============================================================================

func TestListener_Start_WithRouteTLSManager_CertPath(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	routeTLSManager := tlspkg.NewRouteTLSManager()
	routeCfg := &tlspkg.RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err = routeTLSManager.AddRoute("test-route", routeCfg)
	require.NoError(t, err)

	listener, err := NewListener(cfg, handler, WithRouteTLSManager(routeTLSManager))
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Verify TLS config was set from route TLS manager
	assert.NotNil(t, listener.server.TLSConfig)

	err = listener.Stop(ctx)
	require.NoError(t, err)
}

func TestListener_Start_WithTLSManagerOnServer_CoveragePath(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTPS,
		TLS: &config.ListenerTLSConfig{
			Mode:     "SIMPLE",
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler, WithTLSMetrics(tlspkg.NewNopMetrics()))
	require.NoError(t, err)
	require.NotNil(t, listener.tlsManager)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Verify TLS config was set from TLS manager
	assert.NotNil(t, listener.server.TLSConfig)

	err = listener.Stop(ctx)
	require.NoError(t, err)
}

// ============================================================================
// Listener.Start/Stop with TLS (full cycle)
// ============================================================================

func TestListener_StartStop_WithTLS_FullCycle(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTPS,
		TLS: &config.ListenerTLSConfig{
			Mode:     "SIMPLE",
			CertFile: certs.certFile,
			KeyFile:  certs.keyFile,
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	listener, err := NewListener(cfg, handler,
		WithTLSMetrics(tlspkg.NewNopMetrics()),
		WithListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	time.Sleep(10 * time.Millisecond)

	err = listener.Stop(ctx)
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)
	assert.False(t, listener.IsRunning())
}

// ============================================================================
// GRPCListener.configureTLSFromConfig tests
// ============================================================================

func TestGRPCListener_ConfigureTLSFromConfig_WithCertsAndMetrics(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	tlsMetrics := tlspkg.NewNopMetrics()
	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCTLSMetrics(tlsMetrics),
	)
	require.NoError(t, err)

	tlsCfg := &config.TLSConfig{
		Enabled:  true,
		Mode:     "SIMPLE",
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
	}

	opts, err := listener.configureTLSFromConfig(tlsCfg)
	require.NoError(t, err)
	assert.NotEmpty(t, opts, "should return TLS options")
	assert.NotNil(t, listener.tlsManager, "should set TLS manager")
}

func TestGRPCListener_ConfigureTLSFromConfig_WithALPN(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	tlsCfg := &config.TLSConfig{
		Enabled:     true,
		Mode:        "SIMPLE",
		CertFile:    certs.certFile,
		KeyFile:     certs.keyFile,
		RequireALPN: true,
	}

	opts, err := listener.configureTLSFromConfig(tlsCfg)
	require.NoError(t, err)
	// Should have TLS manager option + ALPN enforcement option
	assert.NotEmpty(t, opts)
}

func TestGRPCListener_ConfigureTLSFromConfig_WithMTLS(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	tlsCfg := &config.TLSConfig{
		Enabled:  true,
		Mode:     "MUTUAL",
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		CAFile:   certs.certFile, // Use cert as CA for testing
	}

	opts, err := listener.configureTLSFromConfig(tlsCfg)
	require.NoError(t, err)
	// Should have TLS manager option + client cert metadata option
	assert.NotEmpty(t, opts)
}

// ============================================================================
// handleTLSManagerCreationError tests
// ============================================================================

func TestGRPCListener_HandleTLSManagerCreationError_WithFallback(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	tlsMetrics := tlspkg.NewNopMetrics()
	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCTLSMetrics(tlsMetrics),
	)
	require.NoError(t, err)

	tlsCfg := &config.TLSConfig{
		Enabled:  true,
		Mode:     "SIMPLE",
		CertFile: "/path/to/cert.pem",
		KeyFile:  "/path/to/key.pem",
	}

	opts, err := listener.handleTLSManagerCreationError(tlsCfg, assert.AnError)
	require.NoError(t, err)
	assert.NotEmpty(t, opts, "should return fallback TLS credentials options")
}

func TestGRPCListener_HandleTLSManagerCreationError_NoFallback(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	// No cert/key files - should return error
	tlsCfg := &config.TLSConfig{
		Enabled: true,
		Mode:    "SIMPLE",
	}

	opts, err := listener.handleTLSManagerCreationError(tlsCfg, assert.AnError)
	assert.Error(t, err)
	assert.Nil(t, opts)
	assert.Contains(t, err.Error(), "no fallback cert/key files configured")
}

func TestGRPCListener_HandleTLSManagerCreationError_WithMetrics(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	tlsMetrics := tlspkg.NewNopMetrics()
	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCTLSMetrics(tlsMetrics),
	)
	require.NoError(t, err)

	// No cert/key files - should record metric and return error
	tlsCfg := &config.TLSConfig{
		Enabled: true,
		Mode:    "SIMPLE",
	}

	opts, err := listener.handleTLSManagerCreationError(tlsCfg, assert.AnError)
	assert.Error(t, err)
	assert.Nil(t, opts)
}

// ============================================================================
// GRPCListener.Stop with TLS managers
// ============================================================================

func TestGRPCListener_Stop_WithTLSManagerAndRouteTLSManager(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	routeTLSManager := tlspkg.NewRouteTLSManager()

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCRouteTLSManager(routeTLSManager),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	// Stop should close route TLS manager and proxy
	err = listener.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, listener.IsRunning())
}

func TestGRPCListener_Stop_WithTLSManager_Running(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	// Create a TLS manager in insecure mode
	tlsConfig := &tlspkg.Config{
		Mode: tlspkg.TLSModeInsecure,
	}
	manager, err := tlspkg.NewManager(tlsConfig)
	require.NoError(t, err)

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCTLSManager(manager),
	)
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)

	// Stop should close TLS manager
	err = listener.Stop(ctx)
	require.NoError(t, err)
	assert.False(t, listener.IsRunning())
}

// ============================================================================
// cleanupListenersOnError tests
// ============================================================================

func TestCleanupListenersOnError_WithHTTPListeners(t *testing.T) {
	t.Parallel()

	gwCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{},
		},
	}

	gw, err := New(gwCfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Create a couple of HTTP listeners (not started, so Stop is a no-op)
	l1, err := NewListener(config.Listener{Name: "l1", Port: 0, Protocol: config.ProtocolHTTP},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	l2, err := NewListener(config.Listener{Name: "l2", Port: 0, Protocol: config.ProtocolHTTP},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	// Should not panic
	gw.cleanupListenersOnError([]*Listener{l1, l2}, nil)
}

func TestCleanupListenersOnError_WithGRPCListeners_Coverage(t *testing.T) {
	t.Parallel()

	gwCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{},
		},
	}

	gw, err := New(gwCfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	// Create a gRPC listener (not started, so Stop is a no-op)
	gl1, err := NewGRPCListener(config.Listener{Name: "gl1", Port: 0, Protocol: config.ProtocolGRPC})
	require.NoError(t, err)

	// Should not panic
	gw.cleanupListenersOnError(nil, []*GRPCListener{gl1})
}

func TestCleanupListenersOnError_WithBothTypes(t *testing.T) {
	t.Parallel()

	gwCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{},
		},
	}

	gw, err := New(gwCfg, WithLogger(observability.NopLogger()))
	require.NoError(t, err)

	l1, err := NewListener(config.Listener{Name: "l1", Port: 0, Protocol: config.ProtocolHTTP},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	require.NoError(t, err)

	gl1, err := NewGRPCListener(config.Listener{Name: "gl1", Port: 0, Protocol: config.ProtocolGRPC})
	require.NoError(t, err)

	// Should not panic
	gw.cleanupListenersOnError([]*Listener{l1}, []*GRPCListener{gl1})
}

// ============================================================================
// buildMiddlewareChain - security, CORS, body limit, headers, transform, encoding
// ============================================================================

func TestBuildMiddlewareChain_WithSecurityHeaders(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "security-route",
		Security: &config.SecurityConfig{
			Enabled: true,
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	assert.NotEmpty(t, middlewares, "should have security middleware")
}

func TestBuildMiddlewareChain_WithCORS(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "cors-route",
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"https://example.com"},
			AllowMethods: []string{"GET", "POST"},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	assert.NotEmpty(t, middlewares, "should have CORS middleware")
}

func TestBuildMiddlewareChain_WithBodyLimit(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "body-limit-route",
		RequestLimits: &config.RequestLimitsConfig{
			MaxBodySize: 1024,
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	assert.NotEmpty(t, middlewares, "should have body limit middleware")
}

func TestBuildMiddlewareChain_WithHeaders(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "headers-route",
		Headers: &config.HeaderManipulation{
			Request: &config.HeaderOperation{
				Set: map[string]string{"X-Custom": "value"},
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	assert.NotEmpty(t, middlewares, "should have headers middleware")
}

func TestBuildMiddlewareChain_WithTransform(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "transform-route",
		Transform: &config.TransformConfig{
			Response: &config.ResponseTransformConfig{
				DenyFields: []string{"password", "secret"},
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	assert.NotEmpty(t, middlewares, "should have transform middleware")
}

func TestBuildMiddlewareChain_WithEncoding(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "encoding-route",
		Encoding: &config.EncodingConfig{
			ResponseEncoding: "json",
			JSON: &config.JSONEncodingConfig{
				PrettyPrint: true,
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	assert.NotEmpty(t, middlewares, "should have encoding middleware")
}

func TestBuildMiddlewareChain_AllMiddlewares(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cf := NewCacheFactory(logger, nil)

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		logger,
		WithRouteMiddlewareCacheFactory(cf),
	)

	route := &config.Route{
		Name: "all-middlewares-route",
		Security: &config.SecurityConfig{
			Enabled: true,
		},
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
		},
		RequestLimits: &config.RequestLimitsConfig{
			MaxBodySize: 2048,
		},
		Headers: &config.HeaderManipulation{
			Request: &config.HeaderOperation{
				Set: map[string]string{"X-Test": "value"},
			},
		},
		Cache: &config.CacheConfig{
			Enabled: true,
			TTL:     config.Duration(30 * time.Second),
		},
		Transform: &config.TransformConfig{
			Response: &config.ResponseTransformConfig{
				DenyFields: []string{"internal"},
			},
		},
		Encoding: &config.EncodingConfig{
			ResponseEncoding: "json",
			JSON: &config.JSONEncodingConfig{
				PrettyPrint: true,
			},
		},
	}

	middlewares := manager.buildMiddlewareChain(route)
	// Should have: security + CORS + body limit + headers + cache + transform + encoding = 7
	assert.GreaterOrEqual(t, len(middlewares), 6, "should have multiple middlewares")
}

func TestBuildMiddlewareChain_AllMiddlewares_Integration(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cf := NewCacheFactory(logger, nil)

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		logger,
		WithRouteMiddlewareCacheFactory(cf),
	)

	route := &config.Route{
		Name: "integration-route",
		Security: &config.SecurityConfig{
			Enabled: true,
		},
		CORS: &config.CORSConfig{
			AllowOrigins: []string{"*"},
			AllowMethods: []string{"GET"},
		},
		RequestLimits: &config.RequestLimitsConfig{
			MaxBodySize: 4096,
		},
		Headers: &config.HeaderManipulation{
			Response: &config.HeaderOperation{
				Set: map[string]string{"X-Response": "test"},
			},
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := manager.ApplyMiddleware(inner, route)
	assert.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should pass through all middleware and reach the handler
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// buildRouteAuthzMiddleware tests
// ============================================================================

func TestBuildRouteAuthzMiddleware_NilAuthz(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name:          "test-route",
		Authorization: nil,
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteAuthzMiddleware_DisabledConfig(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(&config.GatewaySpec{}, observability.NopLogger())

	route := &config.Route{
		Name: "test-route",
		Authorization: &config.AuthorizationConfig{
			Enabled: false,
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	assert.Nil(t, mw)
}

func TestBuildRouteAuthzMiddleware_WithRBAC(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	route := &config.Route{
		Name: "authz-route",
		Authorization: &config.AuthorizationConfig{
			Enabled:       true,
			DefaultPolicy: "deny",
			RBAC: &config.RBACConfig{
				Enabled: true,
				Policies: []config.RBACPolicyConfig{
					{
						Name:      "admin-policy",
						Roles:     []string{"admin"},
						Resources: []string{"/api/*"},
						Actions:   []string{"GET", "POST"},
						Effect:    "allow",
					},
				},
			},
		},
	}

	mw := manager.buildRouteAuthzMiddleware(route)
	assert.NotNil(t, mw, "should return authz middleware for valid RBAC config")
}

func TestGetOrCreateAuthzMetrics_LazyInitCoverage(t *testing.T) {
	t.Parallel()

	manager := NewRouteMiddlewareManager(
		&config.GatewaySpec{},
		observability.NopLogger(),
	)

	// Initially nil
	assert.Nil(t, manager.authzMetrics)

	// First call should create metrics
	metrics := manager.getOrCreateAuthzMetrics()
	assert.NotNil(t, metrics)

	// Second call should return same instance
	metrics2 := manager.getOrCreateAuthzMetrics()
	assert.Equal(t, metrics, metrics2)
}

// ============================================================================
// Gateway.createGRPCListener with various options
// ============================================================================

func TestGateway_CreateGRPCListener_WithAllOptions(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()

	gwCfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test-gw"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{},
		},
	}

	gw, err := New(gwCfg,
		WithLogger(observability.NopLogger()),
		WithMetricsRegistry(registry),
		WithAuditLogger(&noopAuditLogger{}),
	)
	require.NoError(t, err)

	listenerCfg := config.Listener{
		Name:     "grpc-test",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	grpcRoutes := []config.GRPCRoute{
		{
			Name: "test-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50052}},
			},
		},
	}

	listener, err := gw.createGRPCListener(listenerCfg, grpcRoutes)
	require.NoError(t, err)
	assert.NotNil(t, listener)
}

// ============================================================================
// GRPCListener.NewGRPCListener with metricsRegistry, authMetrics, vaultClient
// ============================================================================

func TestNewGRPCListener_WithMetricsRegistry(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	registry := prometheus.NewRegistry()
	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCMetricsRegistry(registry),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
	assert.Equal(t, registry, listener.metricsRegistry)
}

// ============================================================================
// GRPCListener.buildTLSOptionsFromRouteTLSManager with metrics
// ============================================================================

func TestGRPCListener_BuildTLSOptionsFromRouteTLSManager_WithMetrics(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	routeTLSManager := tlspkg.NewRouteTLSManager()
	defer routeTLSManager.Close()

	routeCfg := &tlspkg.RouteTLSConfig{
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		SNIHosts: []string{"api.example.com"},
	}
	err = routeTLSManager.AddRoute("test-route", routeCfg)
	require.NoError(t, err)

	tlsMetrics := tlspkg.NewNopMetrics()

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCRouteTLSManager(routeTLSManager),
		WithGRPCTLSMetrics(tlsMetrics),
	)
	require.NoError(t, err)
	assert.NotNil(t, listener)
}

// ============================================================================
// GRPCListener.createTLSManagerFromConfig with mTLS and optional mTLS
// ============================================================================

func TestGRPCListener_CreateTLSManagerFromConfig_WithMTLS(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
		WithGRPCTLSMetrics(tlspkg.NewNopMetrics()),
	)
	require.NoError(t, err)

	tlsCfg := &config.TLSConfig{
		Enabled:  true,
		Mode:     "MUTUAL",
		CertFile: certs.certFile,
		KeyFile:  certs.keyFile,
		CAFile:   certs.certFile,
	}

	manager, err := listener.createTLSManagerFromConfig(tlsCfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestGRPCListener_CreateTLSManagerFromConfig_WithMaxVersion(t *testing.T) {
	t.Parallel()

	certs, err := createFinalBoostTestCertificates(t)
	require.NoError(t, err)
	defer certs.cleanup()

	cfg := config.Listener{
		Name:     "grpc-listener",
		Port:     0,
		Protocol: config.ProtocolGRPC,
	}

	listener, err := NewGRPCListener(cfg,
		WithGRPCListenerLogger(observability.NopLogger()),
	)
	require.NoError(t, err)

	tlsCfg := &config.TLSConfig{
		Enabled:    true,
		Mode:       "SIMPLE",
		CertFile:   certs.certFile,
		KeyFile:    certs.keyFile,
		MaxVersion: "TLS13",
	}

	manager, err := listener.createTLSManagerFromConfig(tlsCfg)
	require.NoError(t, err)
	assert.NotNil(t, manager)
}

// ============================================================================
// Listener.Start with RouteTLSManager (route TLS manager start path)
// ============================================================================

func TestListener_Start_WithRouteTLSManager_StartPath(t *testing.T) {
	t.Parallel()

	cfg := config.Listener{
		Name:     "test-listener",
		Port:     0,
		Protocol: config.ProtocolHTTP,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	routeTLSManager := tlspkg.NewRouteTLSManager()

	listener, err := NewListener(cfg, handler, WithRouteTLSManager(routeTLSManager))
	require.NoError(t, err)

	ctx := context.Background()
	err = listener.Start(ctx)
	require.NoError(t, err)
	assert.True(t, listener.IsRunning())

	err = listener.Stop(ctx)
	require.NoError(t, err)
}

// ============================================================================
// Helper: create test certificates
// ============================================================================

type finalBoostTestCertificates struct {
	certFile string
	keyFile  string
	tempDir  string
}

func (tc *finalBoostTestCertificates) cleanup() {
	if tc.tempDir != "" {
		os.RemoveAll(tc.tempDir)
	}
}

func createFinalBoostTestCertificates(t *testing.T) (*finalBoostTestCertificates, error) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "gateway-final-boost-test-*")
	if err != nil {
		return nil, err
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "api.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"api.example.com", "localhost"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		os.RemoveAll(tempDir)
		return nil, err
	}

	return &finalBoostTestCertificates{
		certFile: certFile,
		keyFile:  keyFile,
		tempDir:  tempDir,
	}, nil
}

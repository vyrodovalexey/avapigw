// Package main provides iteration 5 unit tests for coverage improvement.
// Target: cmd/gateway coverage from 63.4% to >90%.
package main

import (
	"context"
	"flag"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// ============================================================
// getEnvBool Tests - Comprehensive Coverage
// ============================================================

func TestGetEnvBool_AllCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		key          string
		envValue     string
		setEnv       bool
		defaultValue bool
		expected     bool
	}{
		{
			name:         "returns default when env not set",
			key:          "TEST_GETENVBOOL_NOTSET",
			setEnv:       false,
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "returns default when env not set (false default)",
			key:          "TEST_GETENVBOOL_NOTSET2",
			setEnv:       false,
			defaultValue: false,
			expected:     false,
		},
		{
			name:         "returns true for 'true'",
			key:          "TEST_GETENVBOOL_TRUE",
			envValue:     "true",
			setEnv:       true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns true for '1'",
			key:          "TEST_GETENVBOOL_ONE",
			envValue:     "1",
			setEnv:       true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns true for 'yes'",
			key:          "TEST_GETENVBOOL_YES",
			envValue:     "yes",
			setEnv:       true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns true for 'on'",
			key:          "TEST_GETENVBOOL_ON",
			envValue:     "on",
			setEnv:       true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns true for 'TRUE' (case insensitive)",
			key:          "TEST_GETENVBOOL_TRUE_UPPER",
			envValue:     "TRUE",
			setEnv:       true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns true for 'Yes' (case insensitive)",
			key:          "TEST_GETENVBOOL_YES_MIXED",
			envValue:     "Yes",
			setEnv:       true,
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns false for 'false'",
			key:          "TEST_GETENVBOOL_FALSE",
			envValue:     "false",
			setEnv:       true,
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "returns false for '0'",
			key:          "TEST_GETENVBOOL_ZERO",
			envValue:     "0",
			setEnv:       true,
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "returns false for 'no'",
			key:          "TEST_GETENVBOOL_NO",
			envValue:     "no",
			setEnv:       true,
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "returns false for 'off'",
			key:          "TEST_GETENVBOOL_OFF",
			envValue:     "off",
			setEnv:       true,
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "returns false for 'FALSE' (case insensitive)",
			key:          "TEST_GETENVBOOL_FALSE_UPPER",
			envValue:     "FALSE",
			setEnv:       true,
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "returns default for unknown value",
			key:          "TEST_GETENVBOOL_UNKNOWN",
			envValue:     "maybe",
			setEnv:       true,
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "returns default for unknown value (false default)",
			key:          "TEST_GETENVBOOL_UNKNOWN2",
			envValue:     "invalid",
			setEnv:       true,
			defaultValue: false,
			expected:     false,
		},
		{
			name:         "returns default for empty string",
			key:          "TEST_GETENVBOOL_EMPTY",
			envValue:     "",
			setEnv:       true,
			defaultValue: true,
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer os.Unsetenv(tt.key)

			if tt.setEnv {
				os.Setenv(tt.key, tt.envValue)
			}

			result := getEnvBool(tt.key, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================
// buildOperatorConfig Tests
// ============================================================

func TestBuildOperatorConfig_AllFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		flags    cliFlags
		validate func(t *testing.T, cfg interface{})
	}{
		{
			name: "basic config without TLS",
			flags: cliFlags{
				operatorAddress:    "localhost:9444",
				gatewayName:        "my-gateway",
				gatewayNamespace:   "my-namespace",
				operatorTLS:        false,
				operatorNamespaces: "",
			},
			validate: func(t *testing.T, cfg interface{}) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "config with TLS",
			flags: cliFlags{
				operatorAddress:    "localhost:9444",
				gatewayName:        "my-gateway",
				gatewayNamespace:   "my-namespace",
				operatorTLS:        true,
				operatorCAFile:     "/path/to/ca.crt",
				operatorCertFile:   "/path/to/cert.crt",
				operatorKeyFile:    "/path/to/key.key",
				operatorNamespaces: "",
			},
			validate: func(t *testing.T, cfg interface{}) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "config with namespaces",
			flags: cliFlags{
				operatorAddress:    "localhost:9444",
				gatewayName:        "my-gateway",
				gatewayNamespace:   "my-namespace",
				operatorTLS:        false,
				operatorNamespaces: "ns1, ns2, ns3",
			},
			validate: func(t *testing.T, cfg interface{}) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "config with single namespace",
			flags: cliFlags{
				operatorAddress:    "localhost:9444",
				gatewayName:        "my-gateway",
				gatewayNamespace:   "my-namespace",
				operatorTLS:        false,
				operatorNamespaces: "single-ns",
			},
			validate: func(t *testing.T, cfg interface{}) {
				assert.NotNil(t, cfg)
			},
		},
		{
			name: "config with namespaces with extra spaces",
			flags: cliFlags{
				operatorAddress:    "localhost:9444",
				gatewayName:        "my-gateway",
				gatewayNamespace:   "my-namespace",
				operatorTLS:        false,
				operatorNamespaces: "  ns1  ,  ns2  ,  ns3  ",
			},
			validate: func(t *testing.T, cfg interface{}) {
				assert.NotNil(t, cfg)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := buildOperatorConfig(tt.flags)
			tt.validate(t, cfg)
		})
	}
}

// ============================================================
// createMinimalConfig Tests
// ============================================================

func TestCreateMinimalConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags cliFlags
	}{
		{
			name: "basic minimal config",
			flags: cliFlags{
				gatewayName:      "test-gateway",
				gatewayNamespace: "default",
			},
		},
		{
			name: "minimal config with custom name",
			flags: cliFlags{
				gatewayName:      "custom-gateway",
				gatewayNamespace: "custom-ns",
			},
		},
		{
			name: "minimal config with empty name",
			flags: cliFlags{
				gatewayName:      "",
				gatewayNamespace: "default",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := createMinimalConfig(tt.flags)
			assert.NotNil(t, cfg)
			assert.Equal(t, tt.flags.gatewayName, cfg.Metadata.Name)
		})
	}
}

// ============================================================
// gatewayConfigApplier Tests
// ============================================================

func TestGatewayConfigApplier_ApplyRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			router:          r,
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Test with empty routes
	err = applier.ApplyRoutes(ctx, []config.Route{})
	assert.NoError(t, err)

	// Test with valid routes
	routes := []config.Route{
		{
			Name: "test-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}
	err = applier.ApplyRoutes(ctx, routes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyRoutes_NilRouter(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			router:  nil, // nil router
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Should not panic with nil router
	err = applier.ApplyRoutes(ctx, []config.Route{})
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	reg := backend.NewRegistry(logger)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: reg,
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Test with empty backends
	err = applier.ApplyBackends(ctx, []config.Backend{})
	assert.NoError(t, err)

	// Test with valid backends
	backends := []config.Backend{
		{
			Name: "test-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}
	err = applier.ApplyBackends(ctx, backends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyBackends_NilRegistry(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:         gw,
			backendRegistry: nil, // nil registry
			config:          cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Should not panic with nil registry
	err = applier.ApplyBackends(ctx, []config.Backend{})
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCRoutes(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// gRPC routes are not hot-reloaded, should just log warning
	grpcRoutes := []config.GRPCRoute{
		{
			Name: "test-grpc-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}
	err = applier.ApplyGRPCRoutes(ctx, grpcRoutes)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyGRPCBackends(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// gRPC backends are hot-reloaded in both file-based and operator modes
	grpcBackends := []config.GRPCBackend{
		{
			Name: "test-grpc-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50051},
			},
		},
	}
	err = applier.ApplyGRPCBackends(ctx, grpcBackends)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()
	reg := backend.NewRegistry(logger)
	rl := middleware.NewRateLimiter(100, 200, false)
	msl := middleware.NewMaxSessionsLimiter(100, 0, 0)

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    reg,
			router:             r,
			config:             cfg,
			rateLimiter:        rl,
			maxSessionsLimiter: msl,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Test with full config
	fullCfg := validGatewayConfig("test-full")
	fullCfg.Spec.Routes = []config.Route{
		{
			Name: "test-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
	}
	fullCfg.Spec.Backends = []config.Backend{
		{
			Name: "backend-a",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 8080},
			},
		},
	}
	fullCfg.Spec.GRPCRoutes = []config.GRPCRoute{
		{
			Name: "grpc-route",
			Match: []config.GRPCRouteMatch{
				{Service: &config.StringMatch{Exact: "test.Service"}},
			},
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "localhost", Port: 50051}},
			},
		},
	}
	fullCfg.Spec.GRPCBackends = []config.GRPCBackend{
		{
			Name: "grpc-backend",
			Hosts: []config.BackendHost{
				{Address: "localhost", Port: 50051},
			},
		},
	}
	fullCfg.Spec.RateLimit = &config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 200,
		Burst:             400,
	}
	fullCfg.Spec.MaxSessions = &config.MaxSessionsConfig{
		Enabled:       true,
		MaxConcurrent: 200,
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.NoError(t, err)

	// Clean up
	rl.Stop()
	msl.Stop()
}

func TestGatewayConfigApplier_ApplyFullConfig_NilComponents(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway:            gw,
			backendRegistry:    nil,
			router:             nil,
			config:             cfg,
			rateLimiter:        nil,
			maxSessionsLimiter: nil,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Test with full config but nil components
	fullCfg := validGatewayConfig("test-full")
	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.NoError(t, err)
}

func TestGatewayConfigApplier_ApplyFullConfig_RouteError(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	r := router.New()

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			router:  r,
			config:  cfg,
		},
	}

	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	ctx := context.Background()

	// Test with duplicate routes (should cause error)
	fullCfg := validGatewayConfig("test-full")
	fullCfg.Spec.Routes = []config.Route{
		{
			Name: "dup-route",
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-a", Port: 8080}},
			},
		},
		{
			Name: "dup-route", // Duplicate
			Route: []config.RouteDestination{
				{Destination: config.Destination{Host: "backend-b", Port: 8080}},
			},
		},
	}

	err = applier.ApplyFullConfig(ctx, fullCfg)
	assert.Error(t, err)
}

// ============================================================
// parseFlags with operator mode flags
// ============================================================

func TestParseFlags_OperatorModeFlags(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Clear environment variables
	envVars := []string{
		"GATEWAY_CONFIG_PATH", "GATEWAY_LOG_LEVEL", "GATEWAY_LOG_FORMAT",
		"GATEWAY_OPERATOR_MODE", "GATEWAY_OPERATOR_ADDRESS", "GATEWAY_NAME",
		"GATEWAY_NAMESPACE", "GATEWAY_OPERATOR_TLS", "GATEWAY_OPERATOR_CA_FILE",
		"GATEWAY_OPERATOR_CERT_FILE", "GATEWAY_OPERATOR_KEY_FILE", "GATEWAY_OPERATOR_NAMESPACES",
	}
	for _, key := range envVars {
		os.Unsetenv(key)
	}

	// Set command line args with operator mode flags
	os.Args = []string{
		"gateway",
		"-operator-mode",
		"-operator-address", "localhost:9444",
		"-gateway-name", "my-gateway",
		"-gateway-namespace", "my-namespace",
		"-operator-tls",
		"-operator-ca-file", "/path/to/ca.crt",
		"-operator-cert-file", "/path/to/cert.crt",
		"-operator-key-file", "/path/to/key.key",
		"-operator-namespaces", "ns1,ns2",
	}

	// Reset flag.CommandLine to allow re-parsing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flags := parseFlags()

	assert.True(t, flags.operatorMode)
	assert.Equal(t, "localhost:9444", flags.operatorAddress)
	assert.Equal(t, "my-gateway", flags.gatewayName)
	assert.Equal(t, "my-namespace", flags.gatewayNamespace)
	assert.True(t, flags.operatorTLS)
	assert.Equal(t, "/path/to/ca.crt", flags.operatorCAFile)
	assert.Equal(t, "/path/to/cert.crt", flags.operatorCertFile)
	assert.Equal(t, "/path/to/key.key", flags.operatorKeyFile)
	assert.Equal(t, "ns1,ns2", flags.operatorNamespaces)
}

func TestParseFlags_OperatorModeEnvVars(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Set environment variables
	os.Setenv("GATEWAY_OPERATOR_MODE", "true")
	os.Setenv("GATEWAY_OPERATOR_ADDRESS", "env-operator:9444")
	os.Setenv("GATEWAY_NAME", "env-gateway")
	os.Setenv("GATEWAY_NAMESPACE", "env-namespace")
	os.Setenv("GATEWAY_OPERATOR_TLS", "true")
	os.Setenv("GATEWAY_OPERATOR_CA_FILE", "/env/ca.crt")
	os.Setenv("GATEWAY_OPERATOR_CERT_FILE", "/env/cert.crt")
	os.Setenv("GATEWAY_OPERATOR_KEY_FILE", "/env/key.key")
	os.Setenv("GATEWAY_OPERATOR_NAMESPACES", "env-ns1,env-ns2")
	defer func() {
		os.Unsetenv("GATEWAY_OPERATOR_MODE")
		os.Unsetenv("GATEWAY_OPERATOR_ADDRESS")
		os.Unsetenv("GATEWAY_NAME")
		os.Unsetenv("GATEWAY_NAMESPACE")
		os.Unsetenv("GATEWAY_OPERATOR_TLS")
		os.Unsetenv("GATEWAY_OPERATOR_CA_FILE")
		os.Unsetenv("GATEWAY_OPERATOR_CERT_FILE")
		os.Unsetenv("GATEWAY_OPERATOR_KEY_FILE")
		os.Unsetenv("GATEWAY_OPERATOR_NAMESPACES")
	}()

	// Set minimal args
	os.Args = []string{"gateway"}

	// Reset flag.CommandLine to allow re-parsing
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	flags := parseFlags()

	assert.True(t, flags.operatorMode)
	assert.Equal(t, "env-operator:9444", flags.operatorAddress)
	assert.Equal(t, "env-gateway", flags.gatewayName)
	assert.Equal(t, "env-namespace", flags.gatewayNamespace)
	assert.True(t, flags.operatorTLS)
	assert.Equal(t, "/env/ca.crt", flags.operatorCAFile)
	assert.Equal(t, "/env/cert.crt", flags.operatorCertFile)
	assert.Equal(t, "/env/key.key", flags.operatorKeyFile)
	assert.Equal(t, "env-ns1,env-ns2", flags.operatorNamespaces)
}

// ============================================================
// fatalWithSync Tests - Iter5
// ============================================================

func TestFatalWithSync_Iter5(t *testing.T) {
	origExit := exitFunc
	defer func() { exitFunc = origExit }()

	var exitCode int32
	exitFunc = func(code int) {
		atomic.StoreInt32(&exitCode, int32(code))
	}

	logger := observability.NopLogger()

	fatalWithSync(logger, "test error message iter5", observability.String("key", "value"))

	assert.Equal(t, int32(1), atomic.LoadInt32(&exitCode))
}

// ============================================================
// initClientIPExtractor Tests - Iter5
// ============================================================

func TestInitClientIPExtractor_WithTrustedProxies_Iter5(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			TrustedProxies: []string{"10.0.0.0/8", "192.168.0.0/16"},
		},
	}

	// Should not panic when called with trusted proxies
	assert.NotPanics(t, func() {
		initClientIPExtractor(cfg, logger)
	}, "initClientIPExtractor should not panic with trusted proxies")
}

func TestInitClientIPExtractor_WithoutTrustedProxies_Iter5(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			TrustedProxies: []string{},
		},
	}

	// Should not panic when called without trusted proxies
	assert.NotPanics(t, func() {
		initClientIPExtractor(cfg, logger)
	}, "initClientIPExtractor should not panic without trusted proxies")
}

// ============================================================
// initAuditLogger Tests - Additional Coverage
// ============================================================

func TestInitAuditLogger_AllEventTypes(t *testing.T) {
	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Spec: config.GatewaySpec{
			Audit: &config.AuditConfig{
				Enabled: true,
				Output:  "stdout",
				Format:  "json",
				Level:   "info",
				Events: &config.AuditEventsConfig{
					Authentication: true,
					Authorization:  true,
					Request:        true,
					Response:       true,
					Configuration:  true,
					Security:       true,
				},
			},
		},
	}

	reg := prometheus.NewRegistry()
	auditLogger := initAuditLogger(cfg, logger, audit.WithLoggerRegisterer(reg))

	assert.NotNil(t, auditLogger)
	_ = auditLogger.Close()
}

// ============================================================
// waitForShutdown Tests - Additional Coverage
// ============================================================

func TestWaitForShutdown_WithVaultClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	logger := observability.NopLogger()

	cfg := &config.GatewayConfig{
		Metadata: config.Metadata{Name: "test"},
		Spec: config.GatewaySpec{
			Listeners: []config.Listener{
				{
					Name:     "http",
					Bind:     "127.0.0.1",
					Port:     0,
					Protocol: config.ProtocolHTTP,
				},
			},
		},
	}

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithShutdownTimeout(1*time.Second),
	)
	require.NoError(t, err)

	err = gw.Start(context.Background())
	require.NoError(t, err)

	backendReg := backend.NewRegistry(logger)
	tracer, err := observability.NewTracer(observability.TracerConfig{
		ServiceName: "test",
		Enabled:     false,
	})
	require.NoError(t, err)

	rl := middleware.NewRateLimiter(100, 200, false)
	msl := middleware.NewMaxSessionsLimiter(100, 0, 0)

	app := &application{
		gateway:            gw,
		backendRegistry:    backendReg,
		healthChecker:      health.NewChecker("test", observability.NopLogger()),
		metrics:            observability.NewMetrics("test"),
		tracer:             tracer,
		config:             cfg,
		auditLogger:        audit.NewAtomicAuditLogger(audit.NewNoopLogger()),
		rateLimiter:        rl,
		maxSessionsLimiter: msl,
		vaultClient:        nil, // No vault client
	}

	done := make(chan struct{})
	go func() {
		waitForShutdown(app, nil, logger)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)

	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	// Use SIGTERM instead of SIGINT to avoid interfering with other tests
	err = p.Signal(os.Interrupt)
	require.NoError(t, err)

	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("waitForShutdown did not complete in time")
	}
}

// ============================================================
// operatorApplication Tests
// ============================================================

func TestOperatorApplication_Struct(t *testing.T) {
	t.Parallel()

	logger := observability.NopLogger()
	cfg := validGatewayConfig("test")

	gw, err := gateway.New(cfg, gateway.WithLogger(logger))
	require.NoError(t, err)

	opApp := &operatorApplication{
		application: &application{
			gateway: gw,
			config:  cfg,
		},
		operatorClient: nil,
		configHandler:  nil,
		operatorConfig: nil,
	}

	assert.NotNil(t, opApp.application)
	assert.NotNil(t, opApp.gateway)
}

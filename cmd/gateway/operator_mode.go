package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway/operator"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// operatorApplication holds components for operator mode.
type operatorApplication struct {
	*application
	operatorClient *operator.Client
	configHandler  *operator.ConfigHandler
	operatorConfig *operator.Config
}

// runOperatorMode runs the gateway in operator mode.
func runOperatorMode(flags cliFlags, logger observability.Logger) {
	logger.Info("starting avapigw in operator mode",
		observability.String("version", version),
		observability.String("operator_address", flags.operatorAddress),
		observability.String("gateway_name", flags.gatewayName),
		observability.String("gateway_namespace", flags.gatewayNamespace),
	)

	// Build operator configuration
	operatorCfg := buildOperatorConfig(flags)

	// Validate operator configuration
	if err := operatorCfg.Validate(); err != nil {
		fatalWithSync(logger, "invalid operator configuration", observability.Error(err))
		return
	}

	// Create a minimal initial configuration for the gateway
	// The actual configuration will come from the operator
	initialCfg := createMinimalConfig(flags)

	// Initialize client IP extractor with empty trusted proxies
	// This will be updated when configuration is received from operator
	initClientIPExtractor(initialCfg, logger)

	// Initialize the application with minimal config
	app := initApplication(initialCfg, logger)

	// Create operator application
	opApp := &operatorApplication{
		application:    app,
		operatorConfig: operatorCfg,
	}

	// Create config applier that wraps the application
	applier := &gatewayConfigApplier{
		app:    opApp,
		logger: logger,
	}

	// Create config handler
	opApp.configHandler = operator.NewConfigHandler(applier,
		operator.WithHandlerLogger(logger),
	)

	// Create metrics registry for operator client
	registry := prometheus.NewRegistry()

	// Create operator client
	client, err := operator.NewClient(operatorCfg,
		operator.WithLogger(logger),
		operator.WithMetricsRegistry(registry),
		operator.WithConfigUpdateHandler(opApp.configHandler.HandleUpdate),
		operator.WithSnapshotHandler(opApp.configHandler.HandleSnapshot),
	)
	if err != nil {
		fatalWithSync(logger, "failed to create operator client", observability.Error(err))
		return
	}
	opApp.operatorClient = client

	// Run the operator mode gateway
	runOperatorGateway(opApp, logger)
}

// createMinimalConfig creates a minimal gateway configuration for operator mode.
// The actual routes and backends will be populated by the operator.
func createMinimalConfig(flags cliFlags) *config.GatewayConfig {
	cfg := config.DefaultConfig()
	cfg.Metadata.Name = flags.gatewayName

	// Keep default listener for health checks and metrics
	// The operator will provide the actual listener configuration

	return cfg
}

// runOperatorGateway runs the gateway in operator mode.
func runOperatorGateway(opApp *operatorApplication, logger observability.Logger) {
	ctx := context.Background()

	// Start backends
	if err := opApp.backendRegistry.StartAll(ctx); err != nil {
		fatalWithSync(logger, "failed to start backends", observability.Error(err))
		return
	}

	// Start gateway
	if err := opApp.gateway.Start(ctx); err != nil {
		fatalWithSync(logger, "failed to start gateway", observability.Error(err))
		return
	}

	// Start metrics server if enabled
	startMetricsServerIfEnabled(opApp.application, logger)

	// Start operator client
	if err := opApp.operatorClient.Start(ctx); err != nil {
		fatalWithSync(logger, "failed to start operator client", observability.Error(err))
		return
	}

	logger.Info("gateway started in operator mode",
		observability.String("session_id", opApp.operatorClient.SessionID()),
	)

	// Wait for shutdown
	waitForOperatorShutdown(opApp, logger)
}

// waitForOperatorShutdown waits for shutdown signal and performs graceful shutdown.
func waitForOperatorShutdown(opApp *operatorApplication, logger observability.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received shutdown signal", observability.String("signal", sig.String()))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop operator client first
	if opApp.operatorClient != nil {
		logger.Info("stopping operator client")
		if err := opApp.operatorClient.Stop(); err != nil {
			logger.Error("failed to stop operator client", observability.Error(err))
		}
	}

	// Shutdown metrics server if running
	if opApp.metricsServer != nil {
		logger.Info("stopping metrics server")
		if err := opApp.metricsServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("failed to stop metrics server gracefully", observability.Error(err))
		}
	}

	// Stop gateway
	if err := opApp.gateway.Stop(shutdownCtx); err != nil {
		logger.Error("failed to stop gateway gracefully", observability.Error(err))
	}

	// Close Vault client after gateway stops
	if opApp.vaultClient != nil {
		logger.Info("closing vault client")
		if err := opApp.vaultClient.Close(); err != nil {
			logger.Error("failed to close vault client", observability.Error(err))
		}
	}

	// Stop backends
	if err := opApp.backendRegistry.StopAll(shutdownCtx); err != nil {
		logger.Error("failed to stop backends", observability.Error(err))
	}

	// Shutdown tracer
	if err := opApp.tracer.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown tracer", observability.Error(err))
	}

	// Stop rate limiter cleanup goroutine
	if opApp.rateLimiter != nil {
		opApp.rateLimiter.Stop()
	}

	// Stop max sessions limiter
	if opApp.maxSessionsLimiter != nil {
		opApp.maxSessionsLimiter.Stop()
	}

	// Close audit logger
	if opApp.auditLogger != nil {
		if err := opApp.auditLogger.Close(); err != nil {
			logger.Error("failed to close audit logger", observability.Error(err))
		}
	}

	logger.Info("gateway stopped")
}

// gatewayConfigApplier implements operator.ConfigApplier for the gateway.
type gatewayConfigApplier struct {
	app    *operatorApplication
	logger observability.Logger
}

// ApplyRoutes applies HTTP route configuration.
func (a *gatewayConfigApplier) ApplyRoutes(ctx context.Context, routes []config.Route) error {
	a.logger.Info("applying routes from operator",
		observability.Int("count", len(routes)),
	)

	if a.app.router != nil {
		return a.app.router.LoadRoutes(routes)
	}
	return nil
}

// ApplyBackends applies HTTP backend configuration.
func (a *gatewayConfigApplier) ApplyBackends(ctx context.Context, backends []config.Backend) error {
	a.logger.Info("applying backends from operator",
		observability.Int("count", len(backends)),
	)

	if a.app.backendRegistry != nil {
		return a.app.backendRegistry.ReloadFromConfig(ctx, backends)
	}
	return nil
}

// ApplyGRPCRoutes applies gRPC route configuration.
// Note: gRPC routes require gateway restart for full effect.
func (a *gatewayConfigApplier) ApplyGRPCRoutes(ctx context.Context, routes []config.GRPCRoute) error {
	a.logger.Warn("gRPC routes received from operator - gRPC routes are NOT hot-reloaded",
		observability.Int("count", len(routes)),
	)
	// gRPC routes cannot be hot-reloaded, log a warning
	return nil
}

// ApplyGRPCBackends applies gRPC backend configuration.
// Note: gRPC backends require gateway restart for full effect.
func (a *gatewayConfigApplier) ApplyGRPCBackends(ctx context.Context, backends []config.GRPCBackend) error {
	a.logger.Warn("gRPC backends received from operator - gRPC backends are NOT hot-reloaded",
		observability.Int("count", len(backends)),
	)
	// gRPC backends cannot be hot-reloaded, log a warning
	return nil
}

// ApplyFullConfig applies a complete configuration.
func (a *gatewayConfigApplier) ApplyFullConfig(ctx context.Context, cfg *config.GatewayConfig) error {
	a.logger.Info("applying full configuration from operator",
		observability.Int("routes", len(cfg.Spec.Routes)),
		observability.Int("backends", len(cfg.Spec.Backends)),
		observability.Int("grpc_routes", len(cfg.Spec.GRPCRoutes)),
		observability.Int("grpc_backends", len(cfg.Spec.GRPCBackends)),
	)

	// Apply HTTP routes
	if a.app.router != nil && len(cfg.Spec.Routes) > 0 {
		if err := a.app.router.LoadRoutes(cfg.Spec.Routes); err != nil {
			a.logger.Error("failed to apply routes", observability.Error(err))
			return err
		}
	}

	// Apply HTTP backends
	if a.app.backendRegistry != nil && len(cfg.Spec.Backends) > 0 {
		if err := a.app.backendRegistry.ReloadFromConfig(ctx, cfg.Spec.Backends); err != nil {
			a.logger.Error("failed to apply backends", observability.Error(err))
			return err
		}
	}

	// Warn about gRPC configuration
	if len(cfg.Spec.GRPCRoutes) > 0 || len(cfg.Spec.GRPCBackends) > 0 {
		a.logger.Warn("gRPC configuration received from operator - gRPC routes/backends are NOT hot-reloaded",
			observability.Int("grpc_routes", len(cfg.Spec.GRPCRoutes)),
			observability.Int("grpc_backends", len(cfg.Spec.GRPCBackends)),
		)
	}

	// Update rate limiter if configured
	if a.app.rateLimiter != nil && cfg.Spec.RateLimit != nil {
		a.app.rateLimiter.UpdateConfig(cfg.Spec.RateLimit)
	}

	// Update max sessions limiter if configured
	if a.app.maxSessionsLimiter != nil && cfg.Spec.MaxSessions != nil {
		a.app.maxSessionsLimiter.UpdateConfig(cfg.Spec.MaxSessions)
	}

	// Update gateway config
	if err := a.app.gateway.Reload(cfg); err != nil {
		a.logger.Error("failed to reload gateway config", observability.Error(err))
		return err
	}

	// Update stored config
	a.app.config = cfg

	a.logger.Info("full configuration applied successfully")
	return nil
}

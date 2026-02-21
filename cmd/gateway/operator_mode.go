package main

import (
	"context"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway/operator"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// operatorClientInterface abstracts the operator client for testability.
type operatorClientInterface interface {
	Start(ctx context.Context) error
	Stop() error
	SessionID() string
}

// operatorApplication holds components for operator mode.
type operatorApplication struct {
	*application
	operatorClient operatorClientInterface
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

	// Load initial configuration from config file if available.
	// The config file (from Helm configmap) contains correct listener config
	// (TLS, ports, etc.), observability, security, and other settings.
	// Routes and backends will be provided by the operator via CRDs.
	initialCfg := loadOperatorInitialConfig(flags, logger)

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

	// Create config handler with cache invalidation callback.
	// When the operator pushes CRD updates, the invalidator clears
	// both the HTTP route middleware cache and gRPC auth caches so
	// the next request rebuilds from the updated configuration.
	opApp.configHandler = operator.NewConfigHandler(applier,
		operator.WithHandlerLogger(logger),
		operator.WithCacheInvalidator(func() {
			if app.routeMiddlewareMgr != nil {
				app.routeMiddlewareMgr.ClearCache()
				logger.Debug("HTTP route middleware cache invalidated by operator update")
			}
			if app.gateway != nil {
				app.gateway.ClearAllAuthCaches()
				logger.Debug("gRPC auth caches invalidated by operator update")
			}
		}),
	)

	// Use the gateway's existing metrics registry so operator-mode metrics
	// are visible on the same metrics HTTP server that scrapes gateway metrics.
	// Create operator client
	client, err := operator.NewClient(operatorCfg,
		operator.WithLogger(logger),
		operator.WithMetricsRegistry(app.metrics.Registry()),
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

// loadOperatorInitialConfig loads the initial gateway configuration for operator mode.
// It tries to load from the config file first (which contains correct listener/TLS settings
// from the Helm configmap), falling back to a minimal default config.
// Routes and backends are cleared since they will come from the operator.
func loadOperatorInitialConfig(flags cliFlags, logger observability.Logger) *config.GatewayConfig {
	cfg, err := config.LoadConfig(flags.configPath)
	if err != nil {
		logger.Warn("failed to load config file for operator mode, using minimal config",
			observability.String("config_path", flags.configPath),
			observability.Error(err),
		)
		return createMinimalConfig(flags)
	}

	logger.Info("loaded base configuration from file for operator mode",
		observability.String("config_path", flags.configPath),
		observability.Int("listeners", len(cfg.Spec.Listeners)),
	)

	// Clear routes and backends - these will come from the operator via CRDs
	cfg.Spec.Routes = nil
	cfg.Spec.Backends = nil
	cfg.Spec.GRPCRoutes = nil
	cfg.Spec.GRPCBackends = nil

	// Override gateway name if provided via flags
	if flags.gatewayName != "" {
		cfg.Metadata.Name = flags.gatewayName
	}

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
	hook := func(_ context.Context, log observability.Logger) {
		// Stop operator client first so no further config updates arrive
		// during the drain phase.
		if opApp.operatorClient != nil {
			log.Info("stopping operator client")
			if err := opApp.operatorClient.Stop(); err != nil {
				log.Error("failed to stop operator client", observability.Error(err))
			}
		}
	}
	gracefulShutdown(opApp.application, logger, hook)
}

// gatewayConfigApplier implements operator.ConfigApplier for the gateway.
type gatewayConfigApplier struct {
	app    *operatorApplication
	logger observability.Logger
}

// ApplyRoutes applies HTTP route configuration.
func (a *gatewayConfigApplier) ApplyRoutes(_ context.Context, routes []config.Route) error {
	a.logger.Info("applying routes from operator",
		observability.Int("count", len(routes)),
	)

	rm := ensureReloadMetrics(a.app.application)

	if a.app.router != nil {
		if err := a.app.router.LoadRoutes(routes); err != nil {
			rm.configReloadComponentTotal.WithLabelValues("routes", "error").Inc()
			return err
		}
		rm.configReloadComponentTotal.WithLabelValues("routes", "success").Inc()
	}
	return nil
}

// ApplyBackends applies HTTP backend configuration.
func (a *gatewayConfigApplier) ApplyBackends(ctx context.Context, backends []config.Backend) error {
	a.logger.Info("applying backends from operator",
		observability.Int("count", len(backends)),
	)

	rm := ensureReloadMetrics(a.app.application)

	if a.app.backendRegistry != nil {
		if err := a.app.backendRegistry.ReloadFromConfig(ctx, backends); err != nil {
			rm.configReloadComponentTotal.WithLabelValues("backends", "error").Inc()
			return err
		}
		rm.configReloadComponentTotal.WithLabelValues("backends", "success").Inc()
	}
	return nil
}

// ApplyGRPCRoutes applies gRPC route configuration.
// gRPC routes are hot-reloaded via the router's thread-safe LoadRoutes method.
func (a *gatewayConfigApplier) ApplyGRPCRoutes(_ context.Context, routes []config.GRPCRoute) error {
	a.logger.Info("applying gRPC routes from operator",
		observability.Int("count", len(routes)),
	)

	rm := ensureReloadMetrics(a.app.application)

	for _, listener := range a.app.gateway.GetGRPCListeners() {
		if err := listener.LoadRoutes(routes); err != nil {
			a.logger.Error("failed to reload gRPC routes on listener",
				observability.String("listener", listener.Name()),
				observability.Error(err),
			)
			rm.configReloadComponentTotal.WithLabelValues("grpc_routes", "error").Inc()
			return err
		}
	}
	rm.configReloadComponentTotal.WithLabelValues("grpc_routes", "success").Inc()
	return nil
}

// ApplyGRPCBackends applies gRPC backend configuration.
// gRPC backends are hot-reloaded via the backend registry's copy-on-write
// ReloadFromConfig method. After reload, stale connections to removed or
// changed backends are cleaned up.
func (a *gatewayConfigApplier) ApplyGRPCBackends(ctx context.Context, backends []config.GRPCBackend) error {
	a.logger.Info("applying gRPC backends from operator",
		observability.Int("count", len(backends)),
	)

	rm := ensureReloadMetrics(a.app.application)

	// Convert gRPC backends to the shared Backend format
	converted := config.GRPCBackendsToBackends(backends)

	// Reload via the gateway's gRPC backend registry
	if a.app.gateway != nil {
		if err := a.app.gateway.ReloadGRPCBackends(ctx, converted); err != nil {
			a.logger.Error("failed to reload gRPC backends",
				observability.Error(err),
			)
			rm.configReloadComponentTotal.WithLabelValues("grpc_backends", "error").Inc()
			return err
		}
		rm.configReloadComponentTotal.WithLabelValues("grpc_backends", "success").Inc()
	}

	return nil
}

// mergeOperatorConfig merges operator-provided resources into the existing
// gateway config to preserve required fields (APIVersion, Kind, Metadata,
// Listeners) that were initialized from the config file or createMinimalConfig().
func (a *gatewayConfigApplier) mergeOperatorConfig(cfg *config.GatewayConfig) *config.GatewayConfig {
	existing := a.app.config
	if existing == nil {
		existing = config.DefaultConfig()
	}

	return &config.GatewayConfig{
		APIVersion: existing.APIVersion,
		Kind:       existing.Kind,
		Metadata:   existing.Metadata,
		Spec: config.GatewaySpec{
			Listeners:      existing.Spec.Listeners,
			Routes:         cfg.Spec.Routes,
			Backends:       cfg.Spec.Backends,
			GRPCRoutes:     cfg.Spec.GRPCRoutes,
			GRPCBackends:   cfg.Spec.GRPCBackends,
			RateLimit:      cfg.Spec.RateLimit,
			CircuitBreaker: existing.Spec.CircuitBreaker,
			CORS:           existing.Spec.CORS,
			Observability:  existing.Spec.Observability,
			Authentication: existing.Spec.Authentication,
			Authorization:  existing.Spec.Authorization,
			Security:       existing.Spec.Security,
			Audit:          mergeAuditConfig(existing.Spec.Audit, cfg.Spec.Audit),
			RequestLimits:  existing.Spec.RequestLimits,
			MaxSessions:    cfg.Spec.MaxSessions,
			TrustedProxies: existing.Spec.TrustedProxies,
		},
	}
}

// mergeAuditConfig returns the operator's audit config if provided,
// falling back to the existing config. This allows the operator to
// update audit settings via full config pushes.
func mergeAuditConfig(existing, incoming *config.AuditConfig) *config.AuditConfig {
	if incoming != nil {
		return incoming
	}
	return existing
}

// applyMergedComponents applies routes, backends, gRPC routes, and middleware
// updates from the merged configuration.
func (a *gatewayConfigApplier) applyMergedComponents(
	ctx context.Context, merged *config.GatewayConfig,
) error {
	if a.app.router != nil && len(merged.Spec.Routes) > 0 {
		if err := a.app.router.LoadRoutes(merged.Spec.Routes); err != nil {
			a.logger.Error("failed to apply routes", observability.Error(err))
			return err
		}
	}

	if a.app.backendRegistry != nil && len(merged.Spec.Backends) > 0 {
		if err := a.app.backendRegistry.ReloadFromConfig(ctx, merged.Spec.Backends); err != nil {
			a.logger.Error("failed to apply backends", observability.Error(err))
			return err
		}
	}

	if err := a.applyMergedGRPCComponents(ctx, merged); err != nil {
		return err
	}

	if a.app.rateLimiter != nil && merged.Spec.RateLimit != nil {
		a.app.rateLimiter.UpdateConfig(merged.Spec.RateLimit)
	}

	if a.app.maxSessionsLimiter != nil && merged.Spec.MaxSessions != nil {
		a.app.maxSessionsLimiter.UpdateConfig(merged.Spec.MaxSessions)
	}

	// Reload audit logger if audit configuration changed.
	// reloadAuditLogger checks auditConfigChanged internally and
	// handles nil app.auditLogger gracefully.
	reloadAuditLogger(a.app.application, merged, a.logger)

	return nil
}

// applyMergedGRPCComponents applies gRPC routes and backends from the merged configuration.
func (a *gatewayConfigApplier) applyMergedGRPCComponents(
	ctx context.Context, merged *config.GatewayConfig,
) error {
	// Hot-reload gRPC routes via the router's thread-safe LoadRoutes method.
	if len(merged.Spec.GRPCRoutes) > 0 {
		for _, listener := range a.app.gateway.GetGRPCListeners() {
			if err := listener.LoadRoutes(merged.Spec.GRPCRoutes); err != nil {
				a.logger.Error("failed to reload gRPC routes",
					observability.String("listener", listener.Name()),
					observability.Error(err),
				)
				return err
			}
		}
	}

	// Hot-reload gRPC backends via the backend registry's copy-on-write pattern.
	if len(merged.Spec.GRPCBackends) > 0 && a.app.gateway != nil {
		converted := config.GRPCBackendsToBackends(merged.Spec.GRPCBackends)
		if err := a.app.gateway.ReloadGRPCBackends(ctx, converted); err != nil {
			a.logger.Error("failed to reload gRPC backends",
				observability.Error(err),
			)
			return err
		}
	}

	return nil
}

// ApplyFullConfig applies a complete configuration.
// It merges operator-provided resources (routes, backends, etc.) into the existing
// gateway config to preserve required fields (APIVersion, Kind, Metadata, Listeners)
// that were initialized from the config file or createMinimalConfig().
func (a *gatewayConfigApplier) ApplyFullConfig(ctx context.Context, cfg *config.GatewayConfig) error {
	start := time.Now()
	rm := ensureReloadMetrics(a.app.application)

	a.logger.Info("applying full configuration from operator",
		observability.Int("routes", len(cfg.Spec.Routes)),
		observability.Int("backends", len(cfg.Spec.Backends)),
		observability.Int("grpc_routes", len(cfg.Spec.GRPCRoutes)),
		observability.Int("grpc_backends", len(cfg.Spec.GRPCBackends)),
	)

	merged := a.mergeOperatorConfig(cfg)

	if err := a.applyMergedComponents(ctx, merged); err != nil {
		rm.configReloadTotal.WithLabelValues("error").Inc()
		rm.configReloadDuration.Observe(time.Since(start).Seconds())
		return err
	}

	// Reload gateway with the merged config that includes all required fields
	if err := a.app.gateway.Reload(merged); err != nil {
		a.logger.Error("failed to reload gateway config", observability.Error(err))
		rm.configReloadTotal.WithLabelValues("error").Inc()
		rm.configReloadDuration.Observe(time.Since(start).Seconds())
		return err
	}

	// Update stored config with the merged result
	a.app.config = merged

	rm.configReloadTotal.WithLabelValues("success").Inc()
	rm.configReloadDuration.Observe(time.Since(start).Seconds())
	rm.configReloadLastSuccess.SetToCurrentTime()

	a.logger.Info("full configuration applied successfully")
	return nil
}

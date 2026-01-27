// Package main is the entry point for the API Gateway.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/audit"
	"github.com/vyrodovalexey/avapigw/internal/backend"
	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway"
	"github.com/vyrodovalexey/avapigw/internal/health"
	"github.com/vyrodovalexey/avapigw/internal/middleware"
	"github.com/vyrodovalexey/avapigw/internal/observability"
	"github.com/vyrodovalexey/avapigw/internal/proxy"
	"github.com/vyrodovalexey/avapigw/internal/router"
)

// Version information (set at build time).
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

// cliFlags holds command line flags.
type cliFlags struct {
	configPath  string
	logLevel    string
	logFormat   string
	showVersion bool
}

func main() {
	flags := parseFlags()

	if flags.showVersion {
		printVersion()
		return
	}

	logger := initLogger(flags)
	defer func() { _ = logger.Sync() }()

	cfg := loadAndValidateConfig(flags.configPath, logger)
	initClientIPExtractor(cfg, logger)
	app := initApplication(cfg, logger)

	runGateway(app, flags.configPath, logger)
}

// parseFlags parses command line flags.
func parseFlags() cliFlags {
	configPath := flag.String("config", getEnvOrDefault("GATEWAY_CONFIG_PATH", "configs/gateway.yaml"),
		"Path to configuration file")
	logLevel := flag.String("log-level", getEnvOrDefault("GATEWAY_LOG_LEVEL", "info"),
		"Log level (debug, info, warn, error)")
	logFormat := flag.String("log-format", getEnvOrDefault("GATEWAY_LOG_FORMAT", "json"),
		"Log format (json, console)")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	return cliFlags{
		configPath:  *configPath,
		logLevel:    *logLevel,
		logFormat:   *logFormat,
		showVersion: *showVersion,
	}
}

// printVersion prints version information and exits.
func printVersion() {
	fmt.Printf("avapigw version %s\n", version)
	fmt.Printf("  Build time: %s\n", buildTime)
	fmt.Printf("  Git commit: %s\n", gitCommit)
}

// initLogger initializes the logger.
func initLogger(flags cliFlags) observability.Logger {
	logger, err := observability.NewLogger(observability.LogConfig{
		Level:  flags.logLevel,
		Format: flags.logFormat,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	observability.SetGlobalLogger(logger)
	return logger
}

// fatalWithSync logs a fatal message and ensures logger is synced before exit.
func fatalWithSync(logger observability.Logger, msg string, fields ...observability.Field) {
	logger.Error(msg, fields...)
	_ = logger.Sync()
	os.Exit(1)
}

// initClientIPExtractor creates and sets the global ClientIPExtractor
// from the gateway configuration's trusted proxies list.
func initClientIPExtractor(
	cfg *config.GatewayConfig,
	logger observability.Logger,
) {
	proxies := cfg.Spec.TrustedProxies
	extractor := middleware.NewClientIPExtractor(proxies)
	middleware.SetGlobalIPExtractor(extractor)

	if len(proxies) > 0 {
		logger.Info("client IP extraction configured with trusted proxies",
			observability.Int("trusted_proxy_count", len(proxies)),
		)
	} else {
		logger.Info("client IP extraction using RemoteAddr only (no trusted proxies)")
	}
}

// loadAndValidateConfig loads and validates the configuration.
func loadAndValidateConfig(configPath string, logger observability.Logger) *config.GatewayConfig {
	logger.Info("starting avapigw",
		observability.String("version", version),
		observability.String("config", configPath),
	)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fatalWithSync(logger, "failed to load configuration", observability.Error(err))
	}

	if err := config.ValidateConfig(cfg); err != nil {
		fatalWithSync(logger, "invalid configuration", observability.Error(err))
	}

	// Count gRPC and HTTP listeners
	grpcListenerCount := 0
	httpListenerCount := 0
	for _, l := range cfg.Spec.Listeners {
		if l.Protocol == config.ProtocolGRPC {
			grpcListenerCount++
		} else {
			httpListenerCount++
		}
	}

	logger.Info("configuration loaded",
		observability.String("name", cfg.Metadata.Name),
		observability.Int("http_listeners", httpListenerCount),
		observability.Int("grpc_listeners", grpcListenerCount),
		observability.Int("routes", len(cfg.Spec.Routes)),
		observability.Int("grpc_routes", len(cfg.Spec.GRPCRoutes)),
		observability.Int("backends", len(cfg.Spec.Backends)),
		observability.Int("grpc_backends", len(cfg.Spec.GRPCBackends)),
	)

	return cfg
}

// application holds all application components.
type application struct {
	gateway            *gateway.Gateway
	backendRegistry    *backend.Registry
	router             *router.Router
	healthChecker      *health.Checker
	metrics            *observability.Metrics
	metricsServer      *http.Server
	tracer             *observability.Tracer
	config             *config.GatewayConfig
	rateLimiter        *middleware.RateLimiter
	maxSessionsLimiter *middleware.MaxSessionsLimiter
	auditLogger        audit.Logger
}

// initApplication initializes all application components.
func initApplication(cfg *config.GatewayConfig, logger observability.Logger) *application {
	metrics := observability.NewMetrics("gateway")
	tracer := initTracer(cfg, logger)
	healthChecker := health.NewChecker(version)
	auditLogger := initAuditLogger(cfg, logger)

	backendRegistry := backend.NewRegistry(logger)
	if err := backendRegistry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		fatalWithSync(logger, "failed to load backends", observability.Error(err))
	}

	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		fatalWithSync(logger, "failed to load routes", observability.Error(err))
	}

	reverseProxy := proxy.NewReverseProxy(r, backendRegistry, proxy.WithProxyLogger(logger))
	middlewareResult := buildMiddlewareChain(reverseProxy, cfg, logger, metrics, tracer, auditLogger)

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(middlewareResult.handler),
		gateway.WithShutdownTimeout(30*time.Second),
	)
	if err != nil {
		fatalWithSync(logger, "failed to create gateway", observability.Error(err))
	}

	return &application{
		gateway:            gw,
		backendRegistry:    backendRegistry,
		router:             r,
		healthChecker:      healthChecker,
		metrics:            metrics,
		tracer:             tracer,
		config:             cfg,
		rateLimiter:        middlewareResult.rateLimiter,
		maxSessionsLimiter: middlewareResult.maxSessionsLimiter,
		auditLogger:        auditLogger,
	}
}

// initAuditLogger creates an audit logger from the gateway configuration.
// If audit is not configured or disabled, a no-op logger is returned.
func initAuditLogger(cfg *config.GatewayConfig, logger observability.Logger) audit.Logger {
	if cfg.Spec.Audit == nil || !cfg.Spec.Audit.Enabled {
		logger.Info("audit logging disabled")
		return audit.NewNoopLogger()
	}

	auditCfg := &audit.Config{
		Enabled:      cfg.Spec.Audit.Enabled,
		Level:        audit.Level(cfg.Spec.Audit.Level),
		Output:       cfg.Spec.Audit.Output,
		Format:       cfg.Spec.Audit.Format,
		SkipPaths:    cfg.Spec.Audit.SkipPaths,
		RedactFields: cfg.Spec.Audit.RedactFields,
	}

	// Default output to stdout when not specified
	if auditCfg.Output == "" {
		auditCfg.Output = "stdout"
	}

	// Convert events configuration
	if cfg.Spec.Audit.Events != nil {
		auditCfg.Events = &audit.EventsConfig{
			Authentication: cfg.Spec.Audit.Events.Authentication,
			Authorization:  cfg.Spec.Audit.Events.Authorization,
			Request:        cfg.Spec.Audit.Events.Request,
			Response:       cfg.Spec.Audit.Events.Response,
			Configuration:  cfg.Spec.Audit.Events.Configuration,
			Security:       cfg.Spec.Audit.Events.Security,
		}
	}

	auditLogger, err := audit.NewLogger(auditCfg, audit.WithLoggerLogger(logger))
	if err != nil {
		logger.Warn("failed to create audit logger, using noop", observability.Error(err))
		return audit.NewNoopLogger()
	}

	logger.Info("audit logging enabled",
		observability.String("output", auditCfg.Output),
		observability.String("format", auditCfg.GetEffectiveFormat()),
		observability.String("level", string(auditCfg.GetEffectiveLevel())),
	)

	return auditLogger
}

// initTracer initializes the tracer.
func initTracer(cfg *config.GatewayConfig, logger observability.Logger) *observability.Tracer {
	tracerCfg := observability.TracerConfig{
		ServiceName:  "avapigw",
		Enabled:      false,
		SamplingRate: 1.0,
	}

	if cfg.Spec.Observability != nil && cfg.Spec.Observability.Tracing != nil {
		tracerCfg.Enabled = cfg.Spec.Observability.Tracing.Enabled
		tracerCfg.SamplingRate = cfg.Spec.Observability.Tracing.SamplingRate
		tracerCfg.OTLPEndpoint = cfg.Spec.Observability.Tracing.OTLPEndpoint
		if cfg.Spec.Observability.Tracing.ServiceName != "" {
			tracerCfg.ServiceName = cfg.Spec.Observability.Tracing.ServiceName
		}
	}

	tracer, err := observability.NewTracer(tracerCfg)
	if err != nil {
		fatalWithSync(logger, "failed to initialize tracer", observability.Error(err))
	}

	return tracer
}

// runGateway runs the gateway and handles shutdown.
func runGateway(app *application, configPath string, logger observability.Logger) {
	ctx := context.Background()

	if err := app.backendRegistry.StartAll(ctx); err != nil {
		fatalWithSync(logger, "failed to start backends", observability.Error(err))
	}

	if err := app.gateway.Start(ctx); err != nil {
		fatalWithSync(logger, "failed to start gateway", observability.Error(err))
	}

	startMetricsServerIfEnabled(app, logger)
	watcher := startConfigWatcher(app, configPath, logger)

	waitForShutdown(app, watcher, logger)
}

// startMetricsServerIfEnabled starts the metrics server if enabled.
func startMetricsServerIfEnabled(app *application, logger observability.Logger) {
	obs := app.config.Spec.Observability
	if obs == nil || obs.Metrics == nil || !obs.Metrics.Enabled {
		return
	}

	metricsPath := obs.Metrics.Path
	if metricsPath == "" {
		metricsPath = "/metrics"
	}

	metricsPort := obs.Metrics.Port
	if metricsPort == 0 {
		metricsPort = 9090
	}

	app.metricsServer = createMetricsServer(metricsPort, metricsPath, app.metrics, app.healthChecker, logger)
	go runMetricsServer(app.metricsServer, logger)
}

// startConfigWatcher starts the configuration watcher.
func startConfigWatcher(
	app *application,
	configPath string,
	logger observability.Logger,
) *config.Watcher {
	watcher, err := config.NewWatcher(configPath, func(newCfg *config.GatewayConfig) {
		logger.Info("configuration changed, reloading")
		reloadComponents(app, newCfg, logger)
	}, config.WithLogger(logger))

	if err != nil {
		logger.Warn("failed to create config watcher", observability.Error(err))
		return nil
	}

	if err := watcher.Start(context.Background()); err != nil {
		logger.Warn("failed to start config watcher", observability.Error(err))
	}

	return watcher
}

// reloadComponents reloads all gateway components with new config.
// Circuit breaker from sony/gobreaker does not support runtime
// reconfiguration; a gateway restart is required to change its
// threshold or timeout settings.
func reloadComponents(
	app *application,
	newCfg *config.GatewayConfig,
	logger observability.Logger,
) {
	// Reload gateway config (atomic pointer swap)
	if err := app.gateway.Reload(newCfg); err != nil {
		logger.Error("failed to reload gateway config",
			observability.Error(err),
		)
		return
	}

	// Update rate limiter
	if app.rateLimiter != nil && newCfg.Spec.RateLimit != nil {
		app.rateLimiter.UpdateConfig(newCfg.Spec.RateLimit)
	}

	// Update max sessions limiter
	if app.maxSessionsLimiter != nil && newCfg.Spec.MaxSessions != nil {
		app.maxSessionsLimiter.UpdateConfig(newCfg.Spec.MaxSessions)
	}

	// Reload routes
	if app.router != nil {
		if err := app.router.LoadRoutes(newCfg.Spec.Routes); err != nil {
			logger.Error("failed to reload routes",
				observability.Error(err),
			)
		}
	}

	// Reload backends
	if app.backendRegistry != nil {
		ctx, cancel := context.WithTimeout(
			context.Background(), 30*time.Second,
		)
		defer cancel()

		if err := app.backendRegistry.ReloadFromConfig(
			ctx, newCfg.Spec.Backends,
		); err != nil {
			logger.Error("failed to reload backends",
				observability.Error(err),
			)
		}
	}

	app.config = newCfg
	logger.Info("all components reloaded successfully")
}

// waitForShutdown waits for shutdown signal and performs graceful shutdown.
func waitForShutdown(app *application, watcher *config.Watcher, logger observability.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received shutdown signal", observability.String("signal", sig.String()))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if watcher != nil {
		_ = watcher.Stop()
	}

	// Shutdown metrics server if running
	if app.metricsServer != nil {
		logger.Info("stopping metrics server")
		if err := app.metricsServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("failed to stop metrics server gracefully", observability.Error(err))
		}
	}

	if err := app.gateway.Stop(shutdownCtx); err != nil {
		logger.Error("failed to stop gateway gracefully", observability.Error(err))
	}

	if err := app.backendRegistry.StopAll(shutdownCtx); err != nil {
		logger.Error("failed to stop backends", observability.Error(err))
	}

	if err := app.tracer.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown tracer", observability.Error(err))
	}

	// Stop rate limiter cleanup goroutine
	if app.rateLimiter != nil {
		app.rateLimiter.Stop()
	}

	// Stop max sessions limiter
	if app.maxSessionsLimiter != nil {
		app.maxSessionsLimiter.Stop()
	}

	// Close audit logger to flush pending events
	if app.auditLogger != nil {
		if err := app.auditLogger.Close(); err != nil {
			logger.Error("failed to close audit logger", observability.Error(err))
		}
	}

	logger.Info("gateway stopped")
}

// middlewareChainResult holds the result of building the middleware chain.
type middlewareChainResult struct {
	handler            http.Handler
	rateLimiter        *middleware.RateLimiter
	maxSessionsLimiter *middleware.MaxSessionsLimiter
}

// buildMiddlewareChain builds the middleware chain.
// The execution order (outermost executes first):
// Recovery -> RequestID -> Logging -> Tracing -> Audit -> Metrics ->
// CORS -> MaxSessions -> CircuitBreaker -> RateLimit -> [proxy]
//
// Tracing runs before Audit so that trace context (TraceID/SpanID)
// is available in the request context when audit events are created.
func buildMiddlewareChain(
	handler http.Handler,
	cfg *config.GatewayConfig,
	logger observability.Logger,
	metrics *observability.Metrics,
	tracer *observability.Tracer,
	auditLogger audit.Logger,
) middlewareChainResult {
	h := handler
	var rateLimiter *middleware.RateLimiter
	var maxSessionsLimiter *middleware.MaxSessionsLimiter

	if cfg.Spec.RateLimit != nil && cfg.Spec.RateLimit.Enabled {
		var rateLimitMiddleware func(http.Handler) http.Handler
		rateLimitMiddleware, rateLimiter = middleware.RateLimitFromConfig(cfg.Spec.RateLimit, logger)
		h = rateLimitMiddleware(h)
	}

	if cfg.Spec.CircuitBreaker != nil && cfg.Spec.CircuitBreaker.Enabled {
		h = middleware.CircuitBreakerFromConfig(cfg.Spec.CircuitBreaker, logger)(h)
	}

	// Max sessions middleware should be applied early to limit concurrent requests
	if cfg.Spec.MaxSessions != nil && cfg.Spec.MaxSessions.Enabled {
		var maxSessionsMiddleware func(http.Handler) http.Handler
		maxSessionsMiddleware, maxSessionsLimiter = middleware.MaxSessionsFromConfig(cfg.Spec.MaxSessions, logger)
		h = maxSessionsMiddleware(h)
	}

	if cfg.Spec.CORS != nil {
		h = middleware.CORSFromConfig(cfg.Spec.CORS)(h)
	}

	h = observability.MetricsMiddleware(metrics)(h)
	h = middleware.Audit(auditLogger)(h)
	h = observability.TracingMiddleware(tracer)(h)
	h = middleware.Logging(logger)(h)
	h = middleware.RequestID()(h)
	h = middleware.Recovery(logger)(h)

	return middlewareChainResult{
		handler:            h,
		rateLimiter:        rateLimiter,
		maxSessionsLimiter: maxSessionsLimiter,
	}
}

// createMetricsServer creates the metrics HTTP server.
func createMetricsServer(
	port int,
	path string,
	metrics *observability.Metrics,
	healthChecker *health.Checker,
	logger observability.Logger,
) *http.Server {
	mux := http.NewServeMux()
	mux.Handle(path, metrics.Handler())
	mux.HandleFunc("/health", healthChecker.HealthHandler())
	mux.HandleFunc("/ready", healthChecker.ReadinessHandler())
	mux.HandleFunc("/live", healthChecker.LivenessHandler())

	addr := fmt.Sprintf(":%d", port)
	logger.Info("starting metrics server",
		observability.String("address", addr),
		observability.String("metrics_path", path),
	)

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
}

// runMetricsServer runs the metrics HTTP server.
func runMetricsServer(server *http.Server, logger observability.Logger) {
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("metrics server error", observability.Error(err))
	}
}

// getEnvOrDefault returns the environment variable value or a default.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

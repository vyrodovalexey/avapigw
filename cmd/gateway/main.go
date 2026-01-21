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

// loadAndValidateConfig loads and validates the configuration.
func loadAndValidateConfig(configPath string, logger observability.Logger) *config.GatewayConfig {
	logger.Info("starting avapigw",
		observability.String("version", version),
		observability.String("config", configPath),
	)

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.Fatal("failed to load configuration", observability.Error(err))
	}

	if err := config.ValidateConfig(cfg); err != nil {
		logger.Fatal("invalid configuration", observability.Error(err))
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
	gateway         *gateway.Gateway
	backendRegistry *backend.Registry
	healthChecker   *health.Checker
	metrics         *observability.Metrics
	tracer          *observability.Tracer
	config          *config.GatewayConfig
}

// initApplication initializes all application components.
func initApplication(cfg *config.GatewayConfig, logger observability.Logger) *application {
	metrics := observability.NewMetrics("gateway")
	tracer := initTracer(cfg, logger)
	healthChecker := health.NewChecker(version)

	backendRegistry := backend.NewRegistry(logger)
	if err := backendRegistry.LoadFromConfig(cfg.Spec.Backends); err != nil {
		logger.Fatal("failed to load backends", observability.Error(err))
	}

	r := router.New()
	if err := r.LoadRoutes(cfg.Spec.Routes); err != nil {
		logger.Fatal("failed to load routes", observability.Error(err))
	}

	reverseProxy := proxy.NewReverseProxy(r, backendRegistry, proxy.WithProxyLogger(logger))
	handler := buildMiddlewareChain(reverseProxy, cfg, logger, metrics, tracer)

	gw, err := gateway.New(cfg,
		gateway.WithLogger(logger),
		gateway.WithRouteHandler(handler),
		gateway.WithShutdownTimeout(30*time.Second),
	)
	if err != nil {
		logger.Fatal("failed to create gateway", observability.Error(err))
	}

	return &application{
		gateway:         gw,
		backendRegistry: backendRegistry,
		healthChecker:   healthChecker,
		metrics:         metrics,
		tracer:          tracer,
		config:          cfg,
	}
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
		logger.Fatal("failed to initialize tracer", observability.Error(err))
	}

	return tracer
}

// runGateway runs the gateway and handles shutdown.
func runGateway(app *application, configPath string, logger observability.Logger) {
	ctx := context.Background()

	if err := app.backendRegistry.StartAll(ctx); err != nil {
		logger.Fatal("failed to start backends", observability.Error(err))
	}

	if err := app.gateway.Start(ctx); err != nil {
		logger.Fatal("failed to start gateway", observability.Error(err))
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

	go startMetricsServer(metricsPort, metricsPath, app.metrics, app.healthChecker, logger)
}

// startConfigWatcher starts the configuration watcher.
func startConfigWatcher(
	app *application,
	configPath string,
	logger observability.Logger,
) *config.Watcher {
	watcher, err := config.NewWatcher(configPath, func(newCfg *config.GatewayConfig) {
		logger.Info("configuration changed, reloading")
		if reloadErr := app.gateway.Reload(newCfg); reloadErr != nil {
			logger.Error("failed to reload configuration", observability.Error(reloadErr))
		}
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

	if err := app.gateway.Stop(shutdownCtx); err != nil {
		logger.Error("failed to stop gateway gracefully", observability.Error(err))
	}

	if err := app.backendRegistry.StopAll(shutdownCtx); err != nil {
		logger.Error("failed to stop backends", observability.Error(err))
	}

	if err := app.tracer.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown tracer", observability.Error(err))
	}

	logger.Info("gateway stopped")
}

// buildMiddlewareChain builds the middleware chain.
func buildMiddlewareChain(
	handler http.Handler,
	cfg *config.GatewayConfig,
	logger observability.Logger,
	metrics *observability.Metrics,
	tracer *observability.Tracer,
) http.Handler {
	h := handler

	if cfg.Spec.RateLimit != nil && cfg.Spec.RateLimit.Enabled {
		h = middleware.RateLimitFromConfig(cfg.Spec.RateLimit, logger)(h)
	}

	if cfg.Spec.CircuitBreaker != nil && cfg.Spec.CircuitBreaker.Enabled {
		h = middleware.CircuitBreakerFromConfig(cfg.Spec.CircuitBreaker, logger)(h)
	}

	if cfg.Spec.CORS != nil {
		h = middleware.CORSFromConfig(cfg.Spec.CORS)(h)
	}

	h = observability.MetricsMiddleware(metrics)(h)
	h = observability.TracingMiddleware(tracer)(h)
	h = middleware.Logging(logger)(h)
	h = middleware.RequestID()(h)
	h = middleware.Recovery(logger)(h)

	return h
}

// startMetricsServer starts the metrics HTTP server.
func startMetricsServer(
	port int,
	path string,
	metrics *observability.Metrics,
	healthChecker *health.Checker,
	logger observability.Logger,
) {
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

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

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

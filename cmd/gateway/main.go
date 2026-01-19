/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/errgroup"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/gateway/backend"
	"github.com/vyrodovalexey/avapigw/internal/gateway/listener"
	grpcserver "github.com/vyrodovalexey/avapigw/internal/gateway/server/grpc"
	"github.com/vyrodovalexey/avapigw/internal/gateway/server/grpc/interceptor"
	httpserver "github.com/vyrodovalexey/avapigw/internal/gateway/server/http"
	"github.com/vyrodovalexey/avapigw/internal/gateway/server/http/middleware"
	tcpserver "github.com/vyrodovalexey/avapigw/internal/gateway/server/tcp"
	tlsserver "github.com/vyrodovalexey/avapigw/internal/gateway/server/tls"
	"github.com/vyrodovalexey/avapigw/internal/health"
)

// configState holds the current configuration state for hot-reload support.
type configState struct {
	mu          sync.RWMutex
	cfg         *config.Config
	localConfig *config.LocalConfig
}

func (s *configState) GetConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *configState) GetLocalConfig() *config.LocalConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localConfig
}

func (s *configState) Update(cfg *config.Config, localCfg *config.LocalConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.localConfig = localCfg
}

// serverComponents holds all server instances for the gateway.
type serverComponents struct {
	httpServer           *httpserver.Server
	grpcServer           *grpcserver.Server
	tcpServer            *tcpserver.Server
	tlsPassthroughServer *tlsserver.Server
	configWatcher        *config.ConfigWatcher
	listenerMgr          *listener.Manager
	backendMgr           *backend.Manager
	healthHandler        *health.Handler
}

func main() {
	cfg, state, configFilePath, logger := initializeGateway()
	defer func() {
		_ = logger.Sync()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := setupSignalHandler()

	components := createServerComponents(ctx, cfg, logger, cancel)

	g, gCtx := errgroup.WithContext(ctx)
	startAllServers(g, gCtx, cfg, components, state, configFilePath, logger)

	waitForShutdownSignal(sigCh, gCtx, logger)

	performGracefulShutdown(cfg, components, logger)

	cancel()
	if err := g.Wait(); err != nil {
		logger.Error("error during shutdown", zap.Error(err))
	}

	logger.Info("API Gateway shutdown complete")
}

// initializeGateway loads configuration and initializes the logger.
func initializeGateway() (*config.Config, *configState, string, *zap.Logger) {
	loader := config.NewLoader()
	cfg, err := loader.LoadConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	localCfg := loader.GetLocalConfig()
	configFilePath := loader.GetConfigFilePath()

	state := &configState{
		cfg:         cfg,
		localConfig: localCfg,
	}

	logger, err := newLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logger.Info("starting API Gateway",
		zap.Int("httpPort", cfg.HTTPPort),
		zap.Int("healthPort", cfg.HealthPort),
		zap.Int("metricsPort", cfg.MetricsPort),
		zap.String("logLevel", cfg.LogLevel),
		zap.String("configFile", configFilePath),
	)

	return cfg, state, configFilePath, logger
}

// setupSignalHandler sets up OS signal handling for graceful shutdown.
func setupSignalHandler() chan os.Signal {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	return sigCh
}

// createServerComponents creates all server components.
func createServerComponents(
	ctx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	cancel context.CancelFunc,
) *serverComponents {
	listenerMgr := listener.NewManager(logger)

	backendMgr := backend.NewManager(logger)
	if err := backendMgr.Start(ctx); err != nil {
		logger.Error("failed to start backend manager", zap.Error(err))
		cancel()
		os.Exit(1) //nolint:gocritic // exitAfterDefer: cancel() called explicitly above
	}

	healthHandler := health.NewHandlerWithConfig(logger, &health.HandlerConfig{
		ReadinessProbeTimeout: cfg.ReadinessProbeTimeout,
		LivenessProbeTimeout:  cfg.LivenessProbeTimeout,
	})

	httpServer := createHTTPServer(cfg, healthHandler, logger)

	return &serverComponents{
		httpServer:    httpServer,
		listenerMgr:   listenerMgr,
		backendMgr:    backendMgr,
		healthHandler: healthHandler,
	}
}

// createHTTPServer creates and configures the HTTP server.
func createHTTPServer(cfg *config.Config, healthHandler *health.Handler, logger *zap.Logger) *httpserver.Server {
	httpServer := httpserver.NewServer(&httpserver.ServerConfig{
		Port:         cfg.HTTPPort,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}, logger)

	setupMiddleware(httpServer, cfg, logger)
	healthHandler.RegisterRoutes(httpServer.GetEngine())

	return httpServer
}

// startAllServers starts all server goroutines.
func startAllServers(
	g *errgroup.Group,
	gCtx context.Context,
	cfg *config.Config,
	components *serverComponents,
	state *configState,
	configFilePath string,
	logger *zap.Logger,
) {
	startCoreServers(g, gCtx, cfg, components, logger)
	startOptionalServers(g, gCtx, cfg, components, state, configFilePath, logger)
}

// startCoreServers starts the core HTTP, health, and listener servers.
func startCoreServers(
	g *errgroup.Group,
	gCtx context.Context,
	cfg *config.Config,
	components *serverComponents,
	logger *zap.Logger,
) {
	g.Go(func() error {
		logger.Info("starting HTTP server", zap.Int("port", cfg.HTTPPort))
		if err := components.httpServer.Start(gCtx); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	g.Go(func() error {
		return startHealthServer(gCtx, cfg, components.healthHandler, logger)
	})

	if cfg.MetricsEnabled {
		g.Go(func() error {
			return startMetricsServer(gCtx, cfg, logger)
		})
	}

	g.Go(func() error {
		if err := components.listenerMgr.Start(gCtx); err != nil {
			return fmt.Errorf("listener manager error: %w", err)
		}
		return nil
	})
}

// startOptionalServers starts optional servers based on configuration.
func startOptionalServers(
	g *errgroup.Group,
	gCtx context.Context,
	cfg *config.Config,
	components *serverComponents,
	state *configState,
	configFilePath string,
	logger *zap.Logger,
) {
	startConfigWatcher(g, gCtx, cfg, components, state, configFilePath, logger)
	startGRPCServer(g, gCtx, cfg, components, logger)
	startTCPServer(g, gCtx, cfg, components, logger)
	startTLSPassthroughServer(g, gCtx, cfg, components, logger)
}

// startConfigWatcher starts the config watcher if a config file was specified.
func startConfigWatcher(
	g *errgroup.Group,
	gCtx context.Context,
	_ *config.Config,
	components *serverComponents,
	state *configState,
	configFilePath string,
	logger *zap.Logger,
) {
	if configFilePath == "" {
		return
	}

	watcher, err := config.NewConfigWatcher(
		configFilePath,
		createConfigReloadCallback(state, configFilePath, logger),
		config.WithDebounce(500*time.Millisecond),
		config.WithLogger(logger),
	)
	if err != nil {
		logger.Error("failed to create config watcher", zap.Error(err))
		return
	}

	components.configWatcher = watcher
	g.Go(func() error {
		logger.Info("starting config watcher", zap.String("path", configFilePath))
		return watcher.Start(gCtx)
	})
}

// createConfigReloadCallback creates the callback function for config reloads.
func createConfigReloadCallback(state *configState, configFilePath string, logger *zap.Logger) config.ConfigCallback {
	return func(newLocalCfg *config.LocalConfig) error {
		logger.Info("configuration file changed, applying new configuration",
			zap.String("path", configFilePath),
		)

		newCfg := config.MergeConfigs(config.DefaultConfig(), newLocalCfg)
		if err := newCfg.Validate(); err != nil {
			logger.Error("new configuration validation failed", zap.Error(err))
			return err
		}

		state.Update(newCfg, newLocalCfg)
		logger.Info("configuration reloaded successfully",
			zap.Int("routes", len(newLocalCfg.Routes)),
			zap.Int("backends", len(newLocalCfg.Backends)),
			zap.Int("rateLimits", len(newLocalCfg.RateLimits)),
			zap.Int("authPolicies", len(newLocalCfg.AuthPolicies)),
		)
		return nil
	}
}

// startGRPCServer starts the gRPC server if enabled.
func startGRPCServer(
	g *errgroup.Group,
	gCtx context.Context,
	cfg *config.Config,
	components *serverComponents,
	logger *zap.Logger,
) {
	if !cfg.GRPCEnabled {
		return
	}

	components.grpcServer = grpcserver.NewServer(&grpcserver.ServerConfig{
		Port:                 cfg.GRPCPort,
		MaxRecvMsgSize:       cfg.GRPCMaxRecvMsgSize,
		MaxSendMsgSize:       cfg.GRPCMaxSendMsgSize,
		MaxConcurrentStreams: safeIntToUint32(cfg.GRPCMaxConcurrentStreams),
		EnableReflection:     cfg.GRPCEnableReflection,
		EnableHealthCheck:    cfg.GRPCEnableHealthCheck,
	}, components.backendMgr, logger)

	setupGRPCInterceptors(components.grpcServer, cfg, logger)

	g.Go(func() error {
		logger.Info("starting gRPC server", zap.Int("port", cfg.GRPCPort))
		if err := components.grpcServer.Start(gCtx); err != nil {
			return fmt.Errorf("gRPC server error: %w", err)
		}
		return nil
	})
}

// startTCPServer starts the TCP server if enabled.
func startTCPServer(
	g *errgroup.Group,
	gCtx context.Context,
	cfg *config.Config,
	components *serverComponents,
	logger *zap.Logger,
) {
	if !cfg.TCPEnabled {
		return
	}

	components.tcpServer = tcpserver.NewServerWithBackend(&tcpserver.ServerConfig{
		Port:           cfg.TCPPort,
		ReadTimeout:    cfg.TCPReadTimeout,
		WriteTimeout:   cfg.TCPWriteTimeout,
		IdleTimeout:    cfg.TCPIdleTimeout,
		MaxConnections: cfg.TCPMaxConnections,
	}, components.backendMgr, logger)

	g.Go(func() error {
		logger.Info("starting TCP server", zap.Int("port", cfg.TCPPort))
		if err := components.tcpServer.Start(gCtx); err != nil {
			return fmt.Errorf("TCP server error: %w", err)
		}
		return nil
	})
}

// startTLSPassthroughServer starts the TLS passthrough server if enabled.
func startTLSPassthroughServer(
	g *errgroup.Group,
	gCtx context.Context,
	cfg *config.Config,
	components *serverComponents,
	logger *zap.Logger,
) {
	if !cfg.TLSPassthroughEnabled {
		return
	}

	components.tlsPassthroughServer = tlsserver.NewServerWithBackend(&tlsserver.ServerConfig{
		Port:           cfg.TLSPassthroughPort,
		Mode:           tlsserver.TLSModePassthrough,
		ReadTimeout:    cfg.ReadTimeout,
		WriteTimeout:   cfg.WriteTimeout,
		IdleTimeout:    cfg.IdleTimeout,
		MaxConnections: cfg.TCPMaxConnections,
	}, components.backendMgr, logger)

	g.Go(func() error {
		logger.Info("starting TLS passthrough server", zap.Int("port", cfg.TLSPassthroughPort))
		if err := components.tlsPassthroughServer.Start(gCtx); err != nil {
			return fmt.Errorf("TLS passthrough server error: %w", err)
		}
		return nil
	})
}

// waitForShutdownSignal waits for a shutdown signal or context cancellation.
func waitForShutdownSignal(sigCh chan os.Signal, gCtx context.Context, logger *zap.Logger) {
	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
	case <-gCtx.Done():
		logger.Info("context cancelled")
	}
}

// performGracefulShutdown performs graceful shutdown of all components.
func performGracefulShutdown(cfg *config.Config, components *serverComponents, logger *zap.Logger) {
	logger.Info("initiating graceful shutdown", zap.Duration("timeout", cfg.ShutdownTimeout))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	stopServers(shutdownCtx, components, logger)
	stopManagers(shutdownCtx, components, logger)
	logFinalStats(components, logger)
}

// stopServers stops all server instances.
func stopServers(ctx context.Context, components *serverComponents, logger *zap.Logger) {
	if err := components.httpServer.Stop(ctx); err != nil {
		logger.Error("error stopping HTTP server", zap.Error(err))
	}

	if components.grpcServer != nil {
		if err := components.grpcServer.Stop(ctx); err != nil {
			logger.Error("error stopping gRPC server", zap.Error(err))
		}
	}

	if components.tcpServer != nil {
		if err := components.tcpServer.Stop(ctx); err != nil {
			logger.Error("error stopping TCP server", zap.Error(err))
		}
	}

	if components.tlsPassthroughServer != nil {
		if err := components.tlsPassthroughServer.Stop(ctx); err != nil {
			logger.Error("error stopping TLS passthrough server", zap.Error(err))
		}
	}

	if components.configWatcher != nil {
		if err := components.configWatcher.Stop(); err != nil {
			logger.Error("error stopping config watcher", zap.Error(err))
		}
	}
}

// stopManagers stops the listener and backend managers.
func stopManagers(ctx context.Context, components *serverComponents, logger *zap.Logger) {
	if err := components.listenerMgr.Stop(ctx); err != nil {
		logger.Error("error stopping listener manager", zap.Error(err))
	}

	if err := components.backendMgr.Stop(ctx); err != nil {
		logger.Error("error stopping backend manager", zap.Error(err))
	}
}

// logFinalStats logs the final backend manager statistics.
func logFinalStats(components *serverComponents, logger *zap.Logger) {
	stats := components.backendMgr.Stats()
	logger.Info("backend manager final stats",
		zap.Int("totalBackends", stats.TotalBackends),
		zap.Int("healthyBackends", stats.HealthyBackends),
		zap.Int("totalEndpoints", stats.TotalEndpoints),
		zap.Int("healthyEndpoints", stats.HealthyEndpoints),
		zap.Duration("uptime", stats.Uptime),
	)
}

// newLogger creates a new zap logger with the specified level and format.
func newLogger(level, format string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	var cfg zap.Config
	if format == "console" {
		cfg = zap.NewDevelopmentConfig()
	} else {
		cfg = zap.NewProductionConfig()
	}

	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	return cfg.Build()
}

// setupMiddleware configures middleware for the HTTP server.
// All middleware must be registered before the server starts.
// Panics if middleware registration fails (indicates programming error).
func setupMiddleware(server *httpserver.Server, cfg *config.Config, logger *zap.Logger) {
	// Recovery middleware (should be first)
	if err := server.Use(middleware.Recovery(logger)); err != nil {
		logger.Fatal("failed to register recovery middleware", zap.Error(err))
	}

	// Request ID middleware
	if err := server.Use(middleware.RequestID()); err != nil {
		logger.Fatal("failed to register request ID middleware", zap.Error(err))
	}

	// Logging middleware
	if err := server.Use(middleware.LoggingWithConfig(middleware.LoggingConfig{
		Logger:          logger,
		SkipHealthCheck: true,
	})); err != nil {
		logger.Fatal("failed to register logging middleware", zap.Error(err))
	}

	// Tracing middleware (if enabled)
	if cfg.TracingEnabled {
		if err := server.Use(middleware.TracingWithConfig(middleware.TracingConfig{
			ServiceName: cfg.ServiceName,
			SkipPaths:   []string{"/health", "/healthz", "/readyz", "/livez", "/metrics"},
		})); err != nil {
			logger.Fatal("failed to register tracing middleware", zap.Error(err))
		}
	}

	// CORS middleware
	if err := server.Use(middleware.CORS()); err != nil {
		logger.Fatal("failed to register CORS middleware", zap.Error(err))
	}

	// Security headers middleware
	if err := server.Use(middleware.SecurityHeaders()); err != nil {
		logger.Fatal("failed to register security headers middleware", zap.Error(err))
	}

	// Timeout middleware
	if err := server.Use(middleware.Timeout(cfg.ReadTimeout)); err != nil {
		logger.Fatal("failed to register timeout middleware", zap.Error(err))
	}
}

// startHealthServer starts the health check server on a separate port.
func startHealthServer(ctx context.Context, cfg *config.Config, handler *health.Handler, logger *zap.Logger) error {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	handler.RegisterRoutes(engine)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HealthPort),
		Handler:      engine,
		ReadTimeout:  cfg.HealthServerReadTimeout,
		WriteTimeout: cfg.HealthServerWriteTimeout,
	}

	logger.Info("starting health server",
		zap.Int("port", cfg.HealthPort),
		zap.Duration("readTimeout", cfg.HealthServerReadTimeout),
		zap.Duration("writeTimeout", cfg.HealthServerWriteTimeout),
	)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server failed to start", zap.Error(err))
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HealthServerShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("failed to shutdown health server gracefully", zap.Error(err))
			return err
		}
		logger.Info("health server shutdown complete")
		return nil
	case err := <-errCh:
		logger.Error("health server error", zap.Error(err))
		return err
	}
}

// setupGRPCInterceptors configures interceptors for the gRPC server.
func setupGRPCInterceptors(server *grpcserver.Server, cfg *config.Config, logger *zap.Logger) {
	// Recovery interceptor (should be first)
	server.AddUnaryInterceptor(interceptor.UnaryRecoveryInterceptor(logger))
	server.AddStreamInterceptor(interceptor.StreamRecoveryInterceptor(logger))

	// Logging interceptor
	server.AddUnaryInterceptor(interceptor.UnaryLoggingInterceptor(logger))
	server.AddStreamInterceptor(interceptor.StreamLoggingInterceptor(logger))

	// Tracing interceptor (if enabled)
	if cfg.TracingEnabled {
		server.AddUnaryInterceptor(interceptor.UnaryTracingInterceptor())
		server.AddStreamInterceptor(interceptor.StreamTracingInterceptor())
	}
}

// safeIntToUint32 safely converts an int to uint32, clamping to max uint32 if needed.
func safeIntToUint32(v int) uint32 {
	if v < 0 {
		return 0
	}
	if v > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(v)
}

// startMetricsServer starts the metrics server on a separate port.
func startMetricsServer(ctx context.Context, cfg *config.Config, logger *zap.Logger) error {
	mux := http.NewServeMux()

	// Use actual Prometheus metrics handler for exposing application metrics
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.MetricsPort),
		Handler:      mux,
		ReadTimeout:  cfg.MetricsServerReadTimeout,
		WriteTimeout: cfg.MetricsServerWriteTimeout,
	}

	logger.Info("starting metrics server",
		zap.Int("port", cfg.MetricsPort),
		zap.Duration("readTimeout", cfg.MetricsServerReadTimeout),
		zap.Duration("writeTimeout", cfg.MetricsServerWriteTimeout),
	)

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed to start", zap.Error(err))
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.MetricsServerShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("failed to shutdown metrics server gracefully", zap.Error(err))
			return err
		}
		logger.Info("metrics server shutdown complete")
		return nil
	case err := <-errCh:
		logger.Error("metrics server error", zap.Error(err))
		return err
	}
}

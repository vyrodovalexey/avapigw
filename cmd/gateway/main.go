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

func main() {
	// Load configuration with local config support
	loader := config.NewLoader()
	cfg, err := loader.LoadConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Get local config if YAML file was specified
	localCfg := loader.GetLocalConfig()
	configFilePath := loader.GetConfigFilePath()

	// Initialize config state for hot-reload support
	state := &configState{
		cfg:         cfg,
		localConfig: localCfg,
	}

	// Initialize logger
	logger, err := newLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting API Gateway",
		zap.Int("httpPort", cfg.HTTPPort),
		zap.Int("healthPort", cfg.HealthPort),
		zap.Int("metricsPort", cfg.MetricsPort),
		zap.String("logLevel", cfg.LogLevel),
		zap.String("configFile", configFilePath),
	)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create listener manager
	listenerMgr := listener.NewManager(logger)

	// Create and start backend manager
	backendMgr := backend.NewManager(logger)
	if err := backendMgr.Start(ctx); err != nil {
		logger.Error("failed to start backend manager", zap.Error(err))
		os.Exit(1)
	}

	// Create health handler with configurable timeouts
	healthHandler := health.NewHandlerWithConfig(logger, &health.HandlerConfig{
		ReadinessProbeTimeout: cfg.ReadinessProbeTimeout,
		LivenessProbeTimeout:  cfg.LivenessProbeTimeout,
	})

	// Create HTTP server
	httpServer := httpserver.NewServer(&httpserver.ServerConfig{
		Port:         cfg.HTTPPort,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}, logger)

	// Setup middleware
	setupMiddleware(httpServer, cfg, logger)

	// Setup health check routes on the main server
	healthHandler.RegisterRoutes(httpServer.GetEngine())

	// Create error group for managing goroutines
	g, gCtx := errgroup.WithContext(ctx)

	// Start HTTP server
	g.Go(func() error {
		logger.Info("starting HTTP server", zap.Int("port", cfg.HTTPPort))
		if err := httpServer.Start(gCtx); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server error: %w", err)
		}
		return nil
	})

	// Start health server on separate port
	g.Go(func() error {
		return startHealthServer(gCtx, cfg, healthHandler, logger)
	})

	// Start metrics server if enabled
	if cfg.MetricsEnabled {
		g.Go(func() error {
			return startMetricsServer(gCtx, cfg, logger)
		})
	}

	// Start listener manager
	g.Go(func() error {
		if err := listenerMgr.Start(gCtx); err != nil {
			return fmt.Errorf("listener manager error: %w", err)
		}
		return nil
	})

	// Start config watcher if config file was specified
	var configWatcher *config.ConfigWatcher
	if configFilePath != "" {
		configWatcher, err = config.NewConfigWatcher(
			configFilePath,
			func(newLocalCfg *config.LocalConfig) error {
				// Handle configuration reload
				logger.Info("configuration file changed, applying new configuration",
					zap.String("path", configFilePath),
				)

				// Merge new local config with base config
				newCfg := config.MergeConfigs(config.DefaultConfig(), newLocalCfg)

				// Validate the new configuration
				if err := newCfg.Validate(); err != nil {
					logger.Error("new configuration validation failed",
						zap.Error(err),
					)
					return err
				}

				// Update the config state
				state.Update(newCfg, newLocalCfg)

				// Log the reload
				logger.Info("configuration reloaded successfully",
					zap.Int("routes", len(newLocalCfg.Routes)),
					zap.Int("backends", len(newLocalCfg.Backends)),
					zap.Int("rateLimits", len(newLocalCfg.RateLimits)),
					zap.Int("authPolicies", len(newLocalCfg.AuthPolicies)),
				)

				return nil
			},
			config.WithDebounce(500*time.Millisecond),
			config.WithLogger(logger),
		)
		if err != nil {
			logger.Error("failed to create config watcher", zap.Error(err))
			// Continue without hot-reload support
		} else {
			g.Go(func() error {
				logger.Info("starting config watcher",
					zap.String("path", configFilePath),
				)
				return configWatcher.Start(gCtx)
			})
		}
	}

	// Create and start gRPC server if enabled
	var grpcServer *grpcserver.Server
	if cfg.GRPCEnabled {
		grpcServer = grpcserver.NewServer(&grpcserver.ServerConfig{
			Port:                 cfg.GRPCPort,
			MaxRecvMsgSize:       cfg.GRPCMaxRecvMsgSize,
			MaxSendMsgSize:       cfg.GRPCMaxSendMsgSize,
			MaxConcurrentStreams: uint32(cfg.GRPCMaxConcurrentStreams),
			EnableReflection:     cfg.GRPCEnableReflection,
			EnableHealthCheck:    cfg.GRPCEnableHealthCheck,
		}, backendMgr, logger)

		// Add interceptors
		setupGRPCInterceptors(grpcServer, cfg, logger)

		g.Go(func() error {
			logger.Info("starting gRPC server", zap.Int("port", cfg.GRPCPort))
			if err := grpcServer.Start(gCtx); err != nil {
				return fmt.Errorf("gRPC server error: %w", err)
			}
			return nil
		})
	}

	// Create and start TCP server if enabled
	var tcpServer *tcpserver.Server
	if cfg.TCPEnabled {
		tcpServer = tcpserver.NewServerWithBackend(&tcpserver.ServerConfig{
			Port:           cfg.TCPPort,
			ReadTimeout:    cfg.TCPReadTimeout,
			WriteTimeout:   cfg.TCPWriteTimeout,
			IdleTimeout:    cfg.TCPIdleTimeout,
			MaxConnections: cfg.TCPMaxConnections,
		}, backendMgr, logger)

		g.Go(func() error {
			logger.Info("starting TCP server", zap.Int("port", cfg.TCPPort))
			if err := tcpServer.Start(gCtx); err != nil {
				return fmt.Errorf("TCP server error: %w", err)
			}
			return nil
		})
	}

	// Create and start TLS passthrough server if enabled
	var tlsPassthroughServer *tlsserver.Server
	if cfg.TLSPassthroughEnabled {
		tlsPassthroughServer = tlsserver.NewServerWithBackend(&tlsserver.ServerConfig{
			Port:           cfg.TLSPassthroughPort,
			Mode:           tlsserver.TLSModePassthrough,
			ReadTimeout:    cfg.ReadTimeout,
			WriteTimeout:   cfg.WriteTimeout,
			IdleTimeout:    cfg.IdleTimeout,
			MaxConnections: cfg.TCPMaxConnections,
		}, backendMgr, logger)

		g.Go(func() error {
			logger.Info("starting TLS passthrough server", zap.Int("port", cfg.TLSPassthroughPort))
			if err := tlsPassthroughServer.Start(gCtx); err != nil {
				return fmt.Errorf("TLS passthrough server error: %w", err)
			}
			return nil
		})
	}

	// Wait for shutdown signal
	select {
	case sig := <-sigCh:
		logger.Info("received shutdown signal", zap.String("signal", sig.String()))
	case <-gCtx.Done():
		logger.Info("context cancelled")
	}

	// Graceful shutdown
	logger.Info("initiating graceful shutdown", zap.Duration("timeout", cfg.ShutdownTimeout))

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()

	// Stop HTTP server
	if err := httpServer.Stop(shutdownCtx); err != nil {
		logger.Error("error stopping HTTP server", zap.Error(err))
	}

	// Stop gRPC server if running
	if grpcServer != nil {
		if err := grpcServer.Stop(shutdownCtx); err != nil {
			logger.Error("error stopping gRPC server", zap.Error(err))
		}
	}

	// Stop TCP server if running
	if tcpServer != nil {
		if err := tcpServer.Stop(shutdownCtx); err != nil {
			logger.Error("error stopping TCP server", zap.Error(err))
		}
	}

	// Stop TLS passthrough server if running
	if tlsPassthroughServer != nil {
		if err := tlsPassthroughServer.Stop(shutdownCtx); err != nil {
			logger.Error("error stopping TLS passthrough server", zap.Error(err))
		}
	}

	// Stop config watcher if running
	if configWatcher != nil {
		if err := configWatcher.Stop(); err != nil {
			logger.Error("error stopping config watcher", zap.Error(err))
		}
	}

	// Stop listener manager
	if err := listenerMgr.Stop(shutdownCtx); err != nil {
		logger.Error("error stopping listener manager", zap.Error(err))
	}

	// Stop backend manager
	if err := backendMgr.Stop(shutdownCtx); err != nil {
		logger.Error("error stopping backend manager", zap.Error(err))
	}

	// Log backend manager stats before shutdown
	stats := backendMgr.Stats()
	logger.Info("backend manager final stats",
		zap.Int("totalBackends", stats.TotalBackends),
		zap.Int("healthyBackends", stats.HealthyBackends),
		zap.Int("totalEndpoints", stats.TotalEndpoints),
		zap.Int("healthyEndpoints", stats.HealthyEndpoints),
		zap.Duration("uptime", stats.Uptime),
	)

	// Cancel context to stop all goroutines
	cancel()

	// Wait for all goroutines to finish
	if err := g.Wait(); err != nil {
		logger.Error("error during shutdown", zap.Error(err))
	}

	logger.Info("API Gateway shutdown complete")
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
func setupMiddleware(server *httpserver.Server, cfg *config.Config, logger *zap.Logger) {
	// Recovery middleware (should be first)
	server.Use(middleware.Recovery(logger))

	// Request ID middleware
	server.Use(middleware.RequestID())

	// Logging middleware
	server.Use(middleware.LoggingWithConfig(middleware.LoggingConfig{
		Logger:          logger,
		SkipHealthCheck: true,
	}))

	// Tracing middleware (if enabled)
	if cfg.TracingEnabled {
		server.Use(middleware.TracingWithConfig(middleware.TracingConfig{
			ServiceName: cfg.ServiceName,
			SkipPaths:   []string{"/health", "/healthz", "/readyz", "/livez", "/metrics"},
		}))
	}

	// CORS middleware
	server.Use(middleware.CORS())

	// Security headers middleware
	server.Use(middleware.SecurityHeaders())

	// Timeout middleware
	server.Use(middleware.Timeout(cfg.ReadTimeout))
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
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HealthServerShutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
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
			errCh <- err
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.MetricsServerShutdownTimeout)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

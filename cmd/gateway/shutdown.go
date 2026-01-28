package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// runGateway runs the gateway and handles shutdown.
func runGateway(app *application, configPath string, logger observability.Logger) {
	ctx := context.Background()

	if err := app.backendRegistry.StartAll(ctx); err != nil {
		fatalWithSync(logger, "failed to start backends", observability.Error(err))
		return // unreachable in production; allows test to continue
	}

	if err := app.gateway.Start(ctx); err != nil {
		fatalWithSync(logger, "failed to start gateway", observability.Error(err))
		return // unreachable in production; allows test to continue
	}

	startMetricsServerIfEnabled(app, logger)
	watcher := startConfigWatcher(app, configPath, logger)

	waitForShutdown(app, watcher, logger)
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

	// Close Vault client after gateway stops (listeners may need certs during drain)
	if app.vaultClient != nil {
		logger.Info("closing vault client")
		if err := app.vaultClient.Close(); err != nil {
			logger.Error("failed to close vault client", observability.Error(err))
		}
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

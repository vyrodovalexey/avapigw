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

// shutdownTimeout is the maximum time allowed for graceful shutdown.
const shutdownTimeout = 30 * time.Second

// drainWaitDuration is the time to wait after marking health endpoints as
// unhealthy, giving load balancers time to detect the change and stop
// sending new traffic before connections are drained.
const drainWaitDuration = 5 * time.Second

// shutdownHook is a function executed during graceful shutdown before
// the common application components are stopped. It receives the
// shutdown context so it can respect the overall deadline.
type shutdownHook func(ctx context.Context, logger observability.Logger)

// runGateway runs the gateway and handles shutdown.
func runGateway(app *application, configPath string, logger observability.Logger) {
	ctx := context.Background()

	if err := app.backendRegistry.StartAll(ctx); err != nil {
		fatalWithSync(logger, "failed to start backends", observability.Error(err))
		return // unreachable in production; allows test to continue
	}

	// Start gRPC backends (health checks, connections)
	if app.grpcBackendRegistry != nil {
		if err := app.grpcBackendRegistry.StartAll(ctx); err != nil {
			fatalWithSync(logger, "failed to start gRPC backends", observability.Error(err))
			return
		}
	}

	if err := app.gateway.Start(ctx); err != nil {
		fatalWithSync(logger, "failed to start gateway", observability.Error(err))
		return // unreachable in production; allows test to continue
	}

	startMetricsServerIfEnabled(app, logger)
	watcher := startConfigWatcher(ctx, app, configPath, logger)

	waitForShutdown(app, watcher, logger)
}

// waitForShutdown waits for shutdown signal and performs graceful shutdown.
func waitForShutdown(app *application, watcher *config.Watcher, logger observability.Logger) {
	hook := func(_ context.Context, _ observability.Logger) {
		// Stop config watcher before shutting down the gateway so no
		// further reloads are triggered during the drain phase.
		if watcher != nil {
			_ = watcher.Stop()
		}
	}
	gracefulShutdown(app, logger, hook)
}

// gracefulShutdown waits for a termination signal, runs optional
// pre-shutdown hooks, and then tears down all common application
// components in the correct order. Both standalone and operator
// modes share this function to avoid duplicating shutdown logic.
func gracefulShutdown(app *application, logger observability.Logger, hooks ...shutdownHook) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	logger.Info("received shutdown signal", observability.String("signal", sig.String()))

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Step 1: Mark health endpoints as unhealthy (draining) BEFORE draining
	// connections. This allows load balancers to detect the change and stop
	// sending new traffic.
	waitForDrain(shutdownCtx, app, logger)

	// Step 2: Execute pre-shutdown hooks (e.g. stop config watcher, operator client).
	for _, h := range hooks {
		h(shutdownCtx, logger)
	}

	// Step 3: Stop core services and cleanup resources.
	stopCoreServices(shutdownCtx, app, logger)

	logger.Info("gateway stopped")
}

// waitForDrain marks health endpoints as draining and waits for load balancers
// to detect the unhealthy status before connections are drained.
func waitForDrain(ctx context.Context, app *application, logger observability.Logger) {
	if app.healthChecker == nil {
		return
	}

	app.healthChecker.SetDraining(true)
	logger.Info("health endpoints marked as draining, waiting for LB detection",
		observability.Duration("drain_wait", drainWaitDuration),
	)

	// Wait for load balancers to detect the unhealthy status.
	// Use a timer that respects the shutdown context deadline.
	drainTimer := time.NewTimer(drainWaitDuration)
	select {
	case <-drainTimer.C:
		// Drain wait completed normally
	case <-ctx.Done():
		drainTimer.Stop()
		logger.Warn("shutdown context expired during drain wait")
	}
}

// stopCoreServices shuts down the gateway, backends, tracer, and other
// application components in the correct order.
func stopCoreServices(ctx context.Context, app *application, logger observability.Logger) {
	// Shutdown metrics server if running
	if app.metricsServer != nil {
		logger.Info("stopping metrics server")
		if err := app.metricsServer.Shutdown(ctx); err != nil {
			logger.Error("failed to stop metrics server gracefully", observability.Error(err))
		}
	}

	// Stop gateway (drains existing connections)
	if err := app.gateway.Stop(ctx); err != nil {
		logger.Error("failed to stop gateway gracefully", observability.Error(err))
	}

	stopDependencies(ctx, app, logger)
	stopBackgroundWorkers(app, logger)
}

// stopDependencies closes caches, Vault, backends, and tracer in the
// correct dependency order.
func stopDependencies(ctx context.Context, app *application, logger observability.Logger) {
	// Close cache factory before Vault client — caches may depend on Vault
	// for credentials (e.g. Redis auth via Vault KV).
	if app.cacheFactory != nil {
		logger.Info("closing cache factory")
		if err := app.cacheFactory.Close(); err != nil {
			logger.Error("failed to close cache factory", observability.Error(err))
		}
	}

	// Close Vault client after gateway and caches stop (listeners may need certs during drain)
	if app.vaultClient != nil {
		logger.Info("closing vault client")
		if err := app.vaultClient.Close(); err != nil {
			logger.Error("failed to close vault client", observability.Error(err))
		}
	}

	if err := app.backendRegistry.StopAll(ctx); err != nil {
		logger.Error("failed to stop backends", observability.Error(err))
	}

	// Stop gRPC backend registry (health checks, connections)
	if app.grpcBackendRegistry != nil {
		if err := app.grpcBackendRegistry.StopAll(ctx); err != nil {
			logger.Error("failed to stop gRPC backends", observability.Error(err))
		}
	}

	if err := app.tracer.Shutdown(ctx); err != nil {
		logger.Error("failed to shutdown tracer", observability.Error(err))
	}
}

// stopBackgroundWorkers stops rate limiter, max sessions limiter, and
// flushes the audit logger.
func stopBackgroundWorkers(app *application, logger observability.Logger) {
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
}

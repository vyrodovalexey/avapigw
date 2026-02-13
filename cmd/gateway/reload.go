package main

import (
	"context"
	"reflect"
	"time"

	"github.com/vyrodovalexey/avapigw/internal/config"
	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// startConfigWatcher starts the configuration watcher.
func startConfigWatcher(
	ctx context.Context,
	app *application,
	configPath string,
	logger observability.Logger,
) *config.Watcher {
	watcher, err := config.NewWatcher(configPath, func(newCfg *config.GatewayConfig) {
		logger.Info("configuration changed, reloading")
		reloadComponents(ctx, app, newCfg, logger)
	}, config.WithLogger(logger))

	if err != nil {
		logger.Warn("failed to create config watcher", observability.Error(err))
		return nil
	}

	if err := watcher.Start(ctx); err != nil {
		logger.Warn("failed to start config watcher", observability.Error(err))
	}

	return watcher
}

// reloadComponents reloads all gateway components with new config.
// Circuit breaker from sony/gobreaker does not support runtime
// reconfiguration; a gateway restart is required to change its
// threshold or timeout settings.
//
// NOTE: gRPC routes and backends are NOT hot-reloaded. gRPC connections
// are long-lived and streaming must be drained, so changes to gRPC
// configuration require a full gateway restart. Only HTTP routes and
// backends are reloaded here.
func reloadComponents(
	ctx context.Context,
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

	// Warn if gRPC configuration has changed — gRPC routes/backends are NOT hot-reloaded
	if grpcConfigChanged(app.config, newCfg) {
		logger.Warn("gRPC configuration has changed but gRPC routes/backends are NOT hot-reloaded; "+
			"restart the gateway to apply gRPC changes",
			observability.Int("old_grpc_routes", len(app.config.Spec.GRPCRoutes)),
			observability.Int("new_grpc_routes", len(newCfg.Spec.GRPCRoutes)),
			observability.Int("old_grpc_backends", len(app.config.Spec.GRPCBackends)),
			observability.Int("new_grpc_backends", len(newCfg.Spec.GRPCBackends)),
		)
	}

	// Update rate limiter
	if app.rateLimiter != nil && newCfg.Spec.RateLimit != nil {
		app.rateLimiter.UpdateConfig(newCfg.Spec.RateLimit)
	}

	// Update max sessions limiter
	if app.maxSessionsLimiter != nil && newCfg.Spec.MaxSessions != nil {
		app.maxSessionsLimiter.UpdateConfig(newCfg.Spec.MaxSessions)
	}

	// Reload HTTP routes (gRPC routes are NOT reloaded — see function comment)
	if app.router != nil {
		if err := app.router.LoadRoutes(newCfg.Spec.Routes); err != nil {
			logger.Error("failed to reload routes",
				observability.Error(err),
			)
		}
	}

	// Reload HTTP backends (gRPC backends are NOT reloaded — see function comment)
	if app.backendRegistry != nil {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
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

// grpcConfigChanged checks if gRPC routes or backends have changed between configs.
func grpcConfigChanged(oldCfg, newCfg *config.GatewayConfig) bool {
	if oldCfg == nil || newCfg == nil {
		return oldCfg != newCfg
	}
	// Compare gRPC routes and backends using deep equality
	if !reflect.DeepEqual(oldCfg.Spec.GRPCRoutes, newCfg.Spec.GRPCRoutes) {
		return true
	}
	if !reflect.DeepEqual(oldCfg.Spec.GRPCBackends, newCfg.Spec.GRPCBackends) {
		return true
	}
	return false
}
